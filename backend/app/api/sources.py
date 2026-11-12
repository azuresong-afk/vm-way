"""Источники («Сканер»), привязки проектов, импорт прогонов и фоновые задачи."""

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.api.common import not_found, paginate
from app.config import get_settings
from app.db import get_db
from app.deps import Principal, get_project, require
from app.integrations.scanner import ScannerError
from app.models import Job, ScannerSource, ScanRun, SourceLink
from app.rbac import Perm
from app.services import source_secrets
from app.services.importer import client_for

router = APIRouter(tags=["sources"])

# Роли сервисной учётной записи в «Сканере»: чтение — auditor, повторная проверка — operator.
READ_ROLES = {"auditor", "operator"}
VERIFY_ROLES = {"operator"}


def source_out(s: ScannerSource) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "base_url": s.base_url,
        "web_url": s.web_url,
        "username": s.username,
        "has_password": bool(s.secret_enc),
        "verify_tls": s.verify_tls,
        "auto_import": s.auto_import,
        "poll_minutes": s.poll_minutes,
        "sync_false_positives": s.sync_false_positives,
        "last_poll_at": s.last_poll_at,
        "last_error": s.last_error,
        "created_at": s.created_at,
    }


def link_out(link: SourceLink) -> dict:
    return {
        "id": link.id,
        "source_id": link.source_id,
        "source_name": link.source.name,
        "project_id": link.project_id,
        "engagement_id": link.engagement_id,
        "engagement_name": link.engagement_name,
        "created_at": link.created_at,
    }


def run_out(r: ScanRun) -> dict:
    return {
        "id": r.id,
        "project_id": r.project_id,
        "source_id": r.source_id,
        "scanner_run_id": r.scanner_run_id,
        "engagement_id": r.engagement_id,
        "name": r.name,
        "kind": r.kind,
        "status": r.status,
        "modules": r.modules,
        "started_at": r.started_at,
        "finished_at": r.finished_at,
        "imported_at": r.imported_at,
        "imported_by": r.imported_by,
        "stats": r.stats,
    }


def job_out(j: Job) -> dict:
    return {
        "id": j.id,
        "kind": j.kind,
        "project_id": j.project_id,
        "title": j.title,
        "status": j.status,
        "result": j.result,
        "error": j.error,
        "attempts": j.attempts,
        "created_by": j.created_by,
        "created_at": j.created_at,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
        "run_after": j.run_after,
    }


def _url(v: str) -> str:
    v = v.strip()
    if v.startswith("mock://"):
        s = get_settings()
        if not (s.allow_mock_sources or s.demo):
            raise ValueError("встроенный мок «Сканера» доступен только на демо-стенде")
        return v
    if not v.startswith(("https://", "http://")):
        raise ValueError("адрес должен начинаться с https://")
    return v.rstrip("/")


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(max_length=500)
    web_url: str = Field(default="", max_length=500)
    username: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=1024)
    verify_tls: bool = True
    auto_import: bool = True
    poll_minutes: int = Field(default=15, ge=1, le=1440)
    # Отмечать ложные срабатывания в «Сканере» (задача 2.5), нужна роль operator.
    sync_false_positives: bool = False

    @field_validator("base_url")
    @classmethod
    def _u(cls, v: str) -> str:
        return _url(v)


class SourcePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=500)
    web_url: str | None = Field(default=None, max_length=500)
    username: str | None = Field(default=None, max_length=200)
    # Пусто или не передано — пароль не меняется.
    password: str | None = Field(default=None, max_length=1024)
    verify_tls: bool | None = None
    auto_import: bool | None = None
    poll_minutes: int | None = Field(default=None, ge=1, le=1440)
    sync_false_positives: bool | None = None

    @field_validator("base_url")
    @classmethod
    def _u(cls, v: str | None) -> str | None:
        return None if v is None else _url(v)


def _get_source(db: Session, source_id: int) -> ScannerSource:
    s = db.get(ScannerSource, source_id)
    if not s:
        raise not_found("Источник")
    return s


@router.get("/sources")
def list_sources(p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)) -> list[dict]:
    return [source_out(s) for s in db.scalars(select(ScannerSource).order_by(ScannerSource.name))]


@router.post("/sources", status_code=201)
def create_source(
    body: SourceIn, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    data = body.model_dump(exclude={"password"})
    s = ScannerSource(**data)
    db.add(s)
    db.flush()
    if body.password:
        # После flush: пароль шифруется с привязкой к id записи.
        source_secrets.write_password(s, body.password)
    audit.record(
        db,
        p.user,
        "source.create",
        object_type="source",
        object_id=s.id,
        ip=p.ip,
        details={"name": s.name, "base_url": s.base_url, "username": s.username},
    )
    db.commit()
    return source_out(s)


@router.patch("/sources/{source_id}")
def update_source(
    source_id: int,
    body: SourcePatch,
    p: Principal = Depends(require(Perm.SOURCES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    s = _get_source(db, source_id)
    changes = body.model_dump(exclude_none=True, exclude={"password"})
    for k, v in changes.items():
        setattr(s, k, v)
    if body.password:
        source_secrets.write_password(s, body.password)
        changes["password_changed"] = True
    audit.record(db, p.user, "source.update", object_type="source", object_id=s.id, ip=p.ip, details=changes)
    db.commit()
    return source_out(s)


@router.delete("/sources/{source_id}", status_code=204)
def delete_source(
    source_id: int, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> Response:
    s = _get_source(db, source_id)
    if db.scalar(select(SourceLink.id).where(SourceLink.source_id == s.id).limit(1)):
        raise HTTPException(409, "Источник привязан к проектам — сначала снимите привязки")
    if db.scalar(select(ScanRun.id).where(ScanRun.source_id == s.id).limit(1)):
        raise HTTPException(409, "Из источника уже импортированы прогоны — его можно только отключить")
    audit.record(db, p.user, "source.delete", object_type="source", object_id=s.id, ip=p.ip, details={"name": s.name})
    db.delete(s)
    db.commit()
    return Response(status_code=204)


@router.post("/sources/{source_id}/test")
def test_source(
    source_id: int, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    """Проверка связи: вход сервисной учётной записью и её роли в «Сканере»."""
    s = _get_source(db, source_id)
    try:
        me = client_for(s).me()
    except ScannerError as e:
        audit.record(
            db,
            p.user,
            "source.test",
            object_type="source",
            object_id=s.id,
            ip=p.ip,
            result="error",
            details={"error": str(e)},
        )
        db.commit()
        return {"ok": False, "error": str(e)}
    roles = set(me.get("roles", []))
    warnings = []
    if not roles & READ_ROLES:
        warnings.append("У учётной записи нет роли auditor или operator — импорт прогонов не сработает.")
    if not roles & VERIFY_ROLES:
        warnings.append("Нет роли operator — повторная проверка прицельным прогоном будет недоступна.")
        if s.sync_false_positives:
            warnings.append("Нет роли operator — отметка ложных срабатываний в «Сканере» не сработает.")
    elif "host_credentials" not in me.get("permissions", []):
        warnings.append("Нет права host_credentials — проверка пакетов по учётной записи будет недоступна.")
    audit.record(
        db,
        p.user,
        "source.test",
        object_type="source",
        object_id=s.id,
        ip=p.ip,
        details={"username": me.get("username"), "roles": sorted(roles)},
    )
    db.commit()
    return {"ok": True, "username": me.get("username"), "roles": sorted(roles), "warnings": warnings}


@router.get("/sources/{source_id}/engagements")
def source_engagements(
    source_id: int, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> list[dict]:
    s = _get_source(db, source_id)
    try:
        items = client_for(s).engagements()
    except ScannerError as e:
        raise HTTPException(502, str(e))
    linked = {
        lk.engagement_id: lk.project_id for lk in db.scalars(select(SourceLink).where(SourceLink.source_id == s.id))
    }
    return [
        {
            "id": e["id"],
            "name": e["name"],
            "client": e.get("client"),
            "contract_ref": e.get("contract_ref"),
            "linked_project_id": linked.get(e["id"]),
        }
        for e in items
    ]


# --- привязки ---


class LinkIn(BaseModel):
    source_id: int
    engagement_id: int


@router.get("/projects/{project_id}/links")
def list_links(
    project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    get_project(db, project_id, p)
    return [
        link_out(lk)
        for lk in db.scalars(select(SourceLink).where(SourceLink.project_id == project_id).order_by(SourceLink.id))
    ]


@router.post("/projects/{project_id}/links", status_code=201)
def create_link(
    project_id: str, body: LinkIn, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    project = get_project(db, project_id, p)
    s = _get_source(db, body.source_id)
    taken = db.scalar(
        select(SourceLink).where(SourceLink.source_id == s.id, SourceLink.engagement_id == body.engagement_id)
    )
    if taken:
        raise HTTPException(409, "Этот проект «Сканера» уже привязан")
    try:
        eng = client_for(s).engagement(body.engagement_id)
    except ScannerError as e:
        raise HTTPException(422 if e.status == 404 else 502, str(e))
    link = SourceLink(
        source_id=s.id, project_id=project.id, engagement_id=body.engagement_id, engagement_name=eng.get("name", "")
    )
    db.add(link)
    db.flush()
    audit.record(
        db,
        p.user,
        "link.create",
        object_type="link",
        object_id=link.id,
        project_id=project.id,
        ip=p.ip,
        details={"source_id": s.id, "engagement_id": body.engagement_id, "engagement_name": link.engagement_name},
    )
    db.commit()
    db.refresh(link)
    return link_out(link)


@router.delete("/links/{link_id}", status_code=204)
def delete_link(
    link_id: int, p: Principal = Depends(require(Perm.SOURCES_MANAGE)), db: Session = Depends(get_db)
) -> Response:
    link = db.get(SourceLink, link_id)
    if not link:
        raise not_found("Привязка")
    get_project(db, link.project_id, p)
    audit.record(
        db,
        p.user,
        "link.delete",
        object_type="link",
        object_id=link.id,
        project_id=link.project_id,
        ip=p.ip,
        details={"engagement_id": link.engagement_id},
    )
    db.delete(link)
    db.commit()
    return Response(status_code=204)


# --- прогоны и импорт ---


@router.get("/projects/{project_id}/runs")
def list_runs(
    project_id: str,
    response: Response,
    limit: int = 50,
    offset: int = 0,
    kind: str | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(ScanRun).where(ScanRun.project_id == project_id)
    if kind:
        stmt = stmt.where(ScanRun.kind == kind)
    stmt = stmt.order_by(ScanRun.finished_at.desc().nulls_last(), ScanRun.id.desc())
    return [run_out(r) for r in paginate(db, stmt, response, limit, offset)]


@router.get("/projects/{project_id}/scanner-runs")
def scanner_runs(
    project_id: str, link_id: int, p: Principal = Depends(require(Perm.IMPORT)), db: Session = Depends(get_db)
) -> list[dict]:
    """Прогоны «Сканера» по привязке — для выбора, что импортировать по кнопке."""
    get_project(db, project_id, p)
    link = db.get(SourceLink, link_id)
    if not link or link.project_id != project_id:
        raise not_found("Привязка")
    try:
        runs = client_for(link.source).runs(link.engagement_id, limit=50)
    except ScannerError as e:
        raise HTTPException(502, str(e))
    imported = dict(
        db.execute(select(ScanRun.scanner_run_id, ScanRun.id).where(ScanRun.source_id == link.source_id)).all()
    )
    return [
        {
            "id": r["id"],
            "name": r.get("name"),
            "status": r["status"],
            "finished_at": r.get("finished_at"),
            "modules": r.get("modules", []),
            "imported_run_id": imported.get(r["id"]),
        }
        for r in runs
    ]


class ImportIn(BaseModel):
    link_id: int | None = None
    # Не задан — импортировать все новые завершённые прогоны привязок проекта.
    scanner_run_id: int | None = None


@router.post("/projects/{project_id}/import", status_code=202)
def start_import(
    project_id: str, body: ImportIn, p: Principal = Depends(require(Perm.IMPORT)), db: Session = Depends(get_db)
) -> dict:
    project = get_project(db, project_id, p)
    links = list(db.scalars(select(SourceLink).where(SourceLink.project_id == project.id)))
    if body.link_id is not None:
        links = [lk for lk in links if lk.id == body.link_id]
    if not links:
        raise HTTPException(422, "Проект не привязан к «Сканеру»")
    if body.scanner_run_id is not None:
        if len(links) != 1:
            raise HTTPException(422, "Укажите привязку (link_id) для импорта конкретного прогона")
        payload = {"link_id": links[0].id, "scanner_run_id": body.scanner_run_id, "user_id": p.user.id}
        job = jobs.enqueue(
            db,
            "import_run",
            payload,
            project_id=project.id,
            created_by=p.user.username,
            title=f"Импорт прогона {body.scanner_run_id}",
        )
    else:
        payload = {"link_ids": [lk.id for lk in links], "user_id": p.user.id}
        job = jobs.enqueue(
            db,
            "import_pending",
            payload,
            project_id=project.id,
            created_by=p.user.username,
            title="Импорт новых прогонов",
        )
    audit.record(
        db,
        p.user,
        "run.import_requested",
        object_type="job",
        object_id=job.id,
        project_id=project.id,
        ip=p.ip,
        details={k: v for k, v in payload.items() if k != "user_id"},
    )
    db.commit()
    jobs.runner.submit(job.id)
    db.refresh(job)
    return job_out(job)


@router.get("/jobs/{job_id}")
def read_job(job_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    j = db.get(Job, job_id)
    if not j:
        raise not_found("Задача")
    if j.project_id:
        get_project(db, j.project_id, p)
    return job_out(j)


@router.get("/projects/{project_id}/jobs")
def project_jobs(
    project_id: str,
    response: Response,
    active: bool = False,
    limit: int = 20,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(Job).where(Job.project_id == project_id)
    if active:
        stmt = stmt.where(Job.status.in_(["queued", "running"]))
    return [job_out(j) for j in paginate(db, stmt.order_by(Job.id.desc()), response, limit, offset)]
