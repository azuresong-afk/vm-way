"""SSH-учётки проекта и закреплённые ключи хостов (задача 2.3).

Список учёток и хостов видят все (без секретов); заводит, меняет, проверяет учётки и решает судьбу
ключей хостов руководитель (право `credentials_manage`). Секреты только принимаются: в ответах,
журнале и логах их нет."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.api.common import not_found
from app.db import get_db, utcnow
from app.deps import Principal, get_project, require
from app.models import HostKey, SshCredential
from app.rbac import Perm
from app.services import credentials as svc
from app.services.credentials import CredentialError

router = APIRouter(tags=["ssh"])

MAX_CREDENTIALS = 100


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=128)
    auth: Literal["password", "key"] = "password"
    port: int = Field(default=22, ge=1, le=65535)
    become: Literal["sudo", "none"] = "sudo"
    password: str | None = Field(default=None, max_length=svc.MAX_SECRET)
    private_key: str | None = Field(default=None, max_length=svc.MAX_SECRET)
    passphrase: str | None = Field(default=None, max_length=1024)
    become_password: str | None = Field(default=None, max_length=1024)
    hosts: list[str] = Field(default_factory=list, max_length=svc.MAX_SCOPE)
    groups: list[str] = Field(default_factory=list, max_length=100)
    is_active: bool = True
    note: str = Field(default="", max_length=2000)


class CredentialPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    username: str | None = Field(default=None, min_length=1, max_length=128)
    auth: Literal["password", "key"] | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    become: Literal["sudo", "none"] | None = None
    # Секрет меняется, только если передан; пустая строка — «не менять».
    password: str | None = Field(default=None, max_length=svc.MAX_SECRET)
    private_key: str | None = Field(default=None, max_length=svc.MAX_SECRET)
    passphrase: str | None = Field(default=None, max_length=1024)
    become_password: str | None = Field(default=None, max_length=1024)
    clear_become_password: bool = False
    hosts: list[str] | None = Field(default=None, max_length=svc.MAX_SCOPE)
    groups: list[str] | None = Field(default=None, max_length=100)
    is_active: bool | None = None
    note: str | None = Field(default=None, max_length=2000)


class CheckIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


def _err(e: CredentialError) -> HTTPException:
    return HTTPException(e.code, e.message)


def _get(db: Session, credential_id: int, p: Principal) -> SshCredential:
    c = db.get(SshCredential, credential_id)
    if c is None:
        raise not_found("Учётка")
    get_project(db, c.project_id, p)
    return c


def _name_taken(db: Session, project_id: str, name: str, exclude: int | None = None) -> bool:
    stmt = select(SshCredential.id).where(SshCredential.project_id == project_id, SshCredential.name == name.strip())
    if exclude:
        stmt = stmt.where(SshCredential.id != exclude)
    return db.scalar(stmt) is not None


@router.get("/projects/{project_id}/ssh-credentials")
def list_credentials(
    project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    get_project(db, project_id, p)
    return [svc.credential_out(c) for c in svc.project_credentials(db, project_id)]


@router.post("/projects/{project_id}/ssh-credentials", status_code=201)
def create_credential(
    project_id: str,
    body: CredentialIn,
    p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    get_project(db, project_id, p)
    count = db.scalar(select(func.count()).select_from(SshCredential).where(SshCredential.project_id == project_id))
    if count >= MAX_CREDENTIALS:
        raise HTTPException(409, f"В проекте не больше {MAX_CREDENTIALS} учёток")
    if _name_taken(db, project_id, body.name):
        raise HTTPException(409, "Учётка с таким названием уже есть")
    data = body.model_dump()
    secrets = {k: data.pop(k) for k in svc.SECRET_FIELDS}
    c = SshCredential(project_id=project_id, created_by=p.user.id, **data)
    try:
        svc.validate(c, secrets)
    except CredentialError as e:
        raise _err(e)
    db.add(c)
    db.flush()
    svc.write_secrets(c, secrets)
    audit.record(
        db,
        p.user,
        "ssh_credential.create",
        object_type="ssh_credential",
        object_id=c.id,
        project_id=project_id,
        ip=p.ip,
        details=svc.snapshot(c),
    )
    db.commit()
    return svc.credential_out(c)


@router.patch("/ssh-credentials/{credential_id}")
def update_credential(
    credential_id: int,
    body: CredentialPatch,
    p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    c = _get(db, credential_id, p)
    before = svc.snapshot(c)
    changes = body.model_dump(exclude_unset=True)
    clear_become = changes.pop("clear_become_password", False)
    new_secrets = {k: changes.pop(k) for k in svc.SECRET_FIELDS if k in changes}
    if "name" in changes and changes["name"] and _name_taken(db, c.project_id, changes["name"], exclude=c.id):
        raise HTTPException(409, "Учётка с таким названием уже есть")
    for k, v in changes.items():
        if v is None:
            raise HTTPException(422, f"{k}: значение не может быть пустым")
        setattr(c, k, v)
    secrets = svc.read_secrets(c)
    if c.auth != before["auth"]:
        # Сменили способ входа — старый секрет другого вида не переносится.
        secrets = {"become_password": secrets.get("become_password")}
    if "private_key" in new_secrets and new_secrets["private_key"]:
        secrets["passphrase"] = None  # новая фраза — вместе с новым ключом
    for k, v in new_secrets.items():
        if v:
            secrets[k] = v
    if clear_become:
        secrets["become_password"] = None
    try:
        svc.validate(c, secrets)
    except CredentialError as e:
        db.rollback()
        raise _err(e)
    svc.write_secrets(c, secrets)
    c.updated_at = utcnow()
    after = svc.snapshot(c)
    changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    replaced = sorted(k for k, v in new_secrets.items() if v) + (["become_password_cleared"] if clear_become else [])
    if changed or replaced:
        audit.record(
            db,
            p.user,
            "ssh_credential.update",
            object_type="ssh_credential",
            object_id=c.id,
            project_id=c.project_id,
            ip=p.ip,
            # Имена заменённых секретов — без значений.
            details={"name": c.name, "changes": changed, "secrets_replaced": replaced},
        )
    db.commit()
    return svc.credential_out(c)


@router.delete("/ssh-credentials/{credential_id}", status_code=204)
def delete_credential(
    credential_id: int, p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)), db: Session = Depends(get_db)
) -> None:
    c = _get(db, credential_id, p)
    audit.record(
        db,
        p.user,
        "ssh_credential.delete",
        object_type="ssh_credential",
        object_id=c.id,
        project_id=c.project_id,
        ip=p.ip,
        details=svc.snapshot(c),
    )
    db.delete(c)
    db.commit()


@router.post("/ssh-credentials/{credential_id}/check")
def check_credential(
    credential_id: int,
    body: CheckIn,
    p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    """Вход на хост учёткой: `id`, ОС, sudo; закрепление ключа хоста при первом подключении."""
    c = _get(db, credential_id, p)
    host = body.host.strip()
    if host not in svc.project_hosts(db, c.project_id):
        raise HTTPException(422, "Хост не из этого проекта: проверять можно только хосты из прогонов «Сканера»")
    if svc.match(c, host, svc.host_groups(db, c.project_id, host)) is None:
        raise HTTPException(422, "Хост вне охвата учётки")
    result = svc.check(db, c, host, p.user, p.ip)
    db.commit()
    return result


@router.get("/projects/{project_id}/ssh-hosts")
def list_hosts(
    project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    """Хосты проекта: учётка, которой пойдём на хост, и закреплённые ключи."""
    get_project(db, project_id, p)
    return svc.hosts_overview(db, project_id)


def _get_key(db: Session, key_id: int, p: Principal) -> HostKey:
    hk = db.get(HostKey, key_id)
    if hk is None:
        raise not_found("Ключ хоста")
    get_project(db, hk.project_id, p)
    return hk


@router.post("/host-keys/{key_id}/accept")
def accept_key(
    key_id: int, body: ReasonIn, p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    """Принять новый ключ хоста, увиденный при несовпадении (после проверки, что хост переустановлен)."""
    hk = _get_key(db, key_id, p)
    try:
        svc.accept_new_key(db, hk, p.user, body.reason.strip(), p.ip)
    except CredentialError as e:
        raise _err(e)
    db.commit()
    return svc.key_out(hk, {p.user.id: p.user.display_name or p.user.username})


@router.post("/host-keys/{key_id}/reset", status_code=204)
def reset_key(
    key_id: int, body: ReasonIn, p: Principal = Depends(require(Perm.CREDENTIALS_MANAGE)), db: Session = Depends(get_db)
) -> None:
    """Снять закрепление: следующее подключение снова закрепит ключ (TOFU)."""
    hk = _get_key(db, key_id, p)
    svc.reset_key(db, hk, p.user, body.reason.strip(), p.ip)
    db.commit()
