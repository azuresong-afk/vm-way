"""Пользователи и роли (администратор)."""

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.api.common import not_found, paginate
from app.db import get_db
from app.deps import Principal, current_principal, get_project, require
from app.models import Ticket, User
from app.rbac import EXTRA_PERMS, ROLES, Perm, perms_for
from app.security import hash_password

router = APIRouter(tags=["users"])

USERNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$"


def _check_roles(roles: list[str], extra: list[str]) -> None:
    bad = [r for r in roles if r not in ROLES] + [e for e in extra if e not in EXTRA_PERMS]
    if bad:
        raise HTTPException(422, f"Неизвестные роли или права: {', '.join(bad)}")
    if "admin" in roles and len(roles) > 1:
        # Разделение обязанностей: администратор не совмещает рабочие роли.
        raise HTTPException(422, "Роль администратора не совмещается с рабочими ролями")


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "email": u.email,
        "roles": u.roles,
        "extra_perms": u.extra_perms,
        "is_active": u.is_active,
        "must_change_password": u.must_change_password,
        "created_at": u.created_at,
    }


class UserIn(BaseModel):
    username: str = Field(pattern=USERNAME_RE)
    display_name: str = Field(default="", max_length=200)
    email: str = Field(default="", max_length=200)
    password: str = Field(min_length=10, max_length=200)
    roles: list[str] = []
    extra_perms: list[str] = []


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=200)
    email: str | None = Field(default=None, max_length=200)
    roles: list[str] | None = None
    extra_perms: list[str] | None = None
    is_active: bool | None = None


class PasswordIn(BaseModel):
    password: str = Field(min_length=10, max_length=200)

    @field_validator("password")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("пустой пароль")
        return v


@router.get("/roles")
def roles(_: Principal = Depends(current_principal)) -> dict:
    return {
        "roles": [
            {"id": k, "label": v["label"], "perms": sorted(str(p) for p in v["perms"])} for k, v in ROLES.items()
        ],
        "extra_perms": [{"id": str(k), "label": v} for k, v in EXTRA_PERMS.items()],
    }


@router.get("/users")
def list_users(
    response: Response,
    limit: int = 100,
    offset: int = 0,
    p: Principal = Depends(require(Perm.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [user_out(u) for u in paginate(db, select(User).order_by(User.username), response, limit, offset)]


@router.get("/users/assignable")
def assignable(
    project_id: str | None = None, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    """Кому можно назначить заявку: исполнители и руководители. С `project_id` — ещё и загрузка:
    сколько открытых заявок проекта уже на человеке."""
    load: dict[int, int] = {}
    if project_id:
        from app.api.tickets import OPEN_STATUSES

        get_project(db, project_id, p)
        load = dict(
            db.execute(
                select(Ticket.assignee_id, func.count())
                .where(
                    Ticket.project_id == project_id,
                    Ticket.assignee_id.is_not(None),
                    Ticket.status.in_(OPEN_STATUSES),
                )
                .group_by(Ticket.assignee_id)
            ).all()
        )
    out = []
    for u in db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.display_name)):
        if Perm.TICKET_WORK in perms_for(u.roles or [], u.extra_perms or []):
            row = {"id": u.id, "username": u.username, "display_name": u.display_name or u.username, "roles": u.roles}
            if project_id:
                row["open_tickets"] = load.get(u.id, 0)
            out.append(row)
    return out


@router.post("/users", status_code=201)
def create_user(
    body: UserIn, p: Principal = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    _check_roles(body.roles, body.extra_perms)
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "Пользователь с таким именем уже есть")
    u = User(
        username=body.username,
        display_name=body.display_name,
        email=body.email,
        password_hash=hash_password(body.password),
        roles=body.roles,
        extra_perms=body.extra_perms,
        # Пароль знает администратор — при первом входе пользователь задаёт свой.
        must_change_password=True,
    )
    db.add(u)
    db.flush()
    audit.record(
        db,
        p.user,
        "user.create",
        object_type="user",
        object_id=u.id,
        ip=p.ip,
        details={"username": u.username, "roles": u.roles, "extra_perms": u.extra_perms},
    )
    db.commit()
    return user_out(u)


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    body: UserPatch,
    p: Principal = Depends(require(Perm.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    u = db.get(User, user_id)
    if not u:
        raise not_found("Пользователь")
    changes = body.model_dump(exclude_none=True)
    roles = changes.get("roles", u.roles)
    _check_roles(roles, changes.get("extra_perms", u.extra_perms))
    if u.id == p.user.id and ("admin" not in roles or changes.get("is_active") is False):
        raise HTTPException(422, "Нельзя снять с себя роль администратора или отключить себя")
    for k, v in changes.items():
        setattr(u, k, v)
    if "is_active" in changes and not changes["is_active"]:
        u.token_version += 1
    audit.record(db, p.user, "user.update", object_type="user", object_id=u.id, ip=p.ip, details=changes)
    db.commit()
    return user_out(u)


@router.post("/users/{user_id}/password")
def set_password(
    user_id: int,
    body: PasswordIn,
    p: Principal = Depends(require(Perm.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    u = db.get(User, user_id)
    if not u:
        raise not_found("Пользователь")
    u.password_hash = hash_password(body.password)
    u.token_version += 1  # старые сессии перестают действовать
    # После сброса пароль знает администратор — пользователь меняет его при первом входе.
    u.must_change_password = u.id != p.user.id
    audit.record(db, p.user, "user.password_reset", object_type="user", object_id=u.id, ip=p.ip)
    db.commit()
    return {"ok": True}
