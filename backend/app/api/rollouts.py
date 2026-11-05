"""Раскатки (задача 2.4): подготовка по заявке, пробный прогон, утверждение, запуск, стоп, журнал.

Права: смотрят все с `view`; готовит, делает пробный прогон и запускает — `remediate_execute`;
утверждает и отклоняет — `rollout_approve` (руководитель), и это другой человек. Произвольная
команда — `custom_commands`. Отказы по правам и «четырём глазам» пишутся в журнал аудита."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.api.common import not_found, paginate
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import MaintenanceWindow, Project, Rollout, RolloutHost, RolloutStep, Ticket
from app.rbac import Perm
from app.services import rollout_templates as tpl
from app.services import rollouts as svc
from app.services.rollout_templates import TemplateError
from app.services.rollouts import RolloutError
from app.services.workflow import Actor

router = APIRouter(tags=["rollouts"])


def _actor(p: Principal) -> Actor:
    return Actor(user=p.user, perms=p.perms, ip=p.ip)


def _fail(db: Session, e: RolloutError | TemplateError) -> HTTPException:
    db.rollback()
    return HTTPException(e.code, e.message)


def _get(db: Session, rollout_id: int, p: Principal, lock: bool = False) -> Rollout:
    stmt = select(Rollout).where(Rollout.id == rollout_id)
    if lock:
        stmt = stmt.with_for_update()
    r = db.scalars(stmt).first()
    if r is None:
        raise not_found("Раскатка")
    get_project(db, r.project_id, p)
    return r


def _ticket(db: Session, ticket_id: int, p: Principal, lock: bool = False) -> Ticket:
    stmt = select(Ticket).where(Ticket.id == ticket_id)
    if lock:
        stmt = stmt.with_for_update()
    t = db.scalars(stmt).first()
    if t is None:
        raise not_found("Заявка")
    get_project(db, t.project_id, p)
    return t


class RolloutIn(BaseModel):
    template: Literal["package", "kernel", "service", "custom"]
    manager: str = Field(default="", max_length=16)
    packages: list[str] = Field(default_factory=list, max_length=tpl.MAX_PACKAGES)
    fixed_version: str = Field(default="", max_length=200)
    service: str = Field(default="", max_length=200)
    command: str = Field(default="", max_length=tpl.MAX_COMMAND)
    hosts: list[str] = Field(default_factory=list, max_length=svc.MAX_HOSTS)
    canary_host: str = Field(default="", max_length=255)
    window_id: int | None = None
    batch_percent: int = Field(default=10, ge=1, le=100)
    failure_threshold: int = Field(default=10, ge=0, le=100)
    note: str = Field(default="", max_length=2000)


class ApproveIn(BaseModel):
    allow_reboot: bool = False
    outside_window: bool = False
    outside_window_reason: str = Field(default="", max_length=1000)
    custom_ack: bool = False
    note: str = Field(default="", max_length=2000)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class OptionalReasonIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class SettingsIn(BaseModel):
    rollout_parallelism: int = Field(ge=1, le=50)


@router.get("/rollout-meta")
def meta(p: Principal = Depends(require(Perm.VIEW))) -> dict:
    return {
        "templates": [{"id": k, "label": v} for k, v in tpl.TEMPLATES.items()],
        "managers": [{"id": k, "label": v} for k, v in tpl.MANAGERS.items()],
        "statuses": [{"id": k, "label": v} for k, v in svc.STATUSES.items()],
        "host_statuses": [{"id": k, "label": v} for k, v in svc.HOST_STATUSES.items()],
        "name_pattern": tpl.NAME_RE.pattern,
    }


@router.get("/tickets/{ticket_id}/rollout-draft")
def draft(ticket_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    """Предложение для формы «Подготовить раскатку»: шаблон, пакеты, хосты, канарейка, окно."""
    t = _ticket(db, ticket_id, p)
    windows = db.scalars(
        select(MaintenanceWindow)
        .where(
            MaintenanceWindow.project_id == t.project_id,
            MaintenanceWindow.kind != "blackout",
            MaintenanceWindow.is_active.is_(True),
        )
        .order_by(MaintenanceWindow.id)
    )
    active = svc.active_for_ticket(db, t.id)
    problems = []
    for name in (t.action or {}).get("packages") or []:
        try:
            tpl.check_name(name)
        except TemplateError as e:
            problems.append(e.message)
    return {
        **svc.defaults(db, t),
        "windows": [{"id": w.id, "name": w.name} for w in windows],
        "active_rollout_id": active.id if active else None,
        "can_prepare": p.can(Perm.REMEDIATE_EXECUTE),
        "can_custom": p.can(Perm.CUSTOM_COMMANDS),
        "problems": problems,
    }


@router.post("/tickets/{ticket_id}/rollouts", status_code=201)
def create(
    ticket_id: int,
    body: RolloutIn,
    p: Principal = Depends(require(Perm.REMEDIATE_EXECUTE)),
    db: Session = Depends(get_db),
) -> dict:
    t = _ticket(db, ticket_id, p, lock=True)
    data = body.model_dump()
    if body.template != "custom":
        data["command"] = []
    try:
        r = svc.create(db, t, _actor(p), data)
    except (RolloutError, TemplateError) as e:
        if isinstance(e, TemplateError) or e.code == 403:
            audit.record_separately(
                p.user,
                "rollout.create",
                object_type="ticket",
                object_id=t.id,
                project_id=t.project_id,
                result="denied",
                ip=p.ip,
                details={"ticket_id": t.id, "reason": e.message, "template": body.template},
            )
        raise _fail(db, e)
    db.commit()
    db.refresh(r)
    return svc.rollout_out(db, r, _actor(p), detail=True)


@router.get("/projects/{project_id}/rollouts")
def list_rollouts(
    project_id: str,
    response: Response,
    status: list[str] = Query(default=[]),
    ticket_id: int | None = None,
    active: bool = False,
    limit: int = 50,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(Rollout).where(Rollout.project_id == project_id)
    if status:
        stmt = stmt.where(Rollout.status.in_(status))
    if active:
        stmt = stmt.where(Rollout.status.in_(svc.OPEN))
    if ticket_id:
        stmt = stmt.where(Rollout.ticket_id == ticket_id)
    rows = paginate(db, stmt.order_by(Rollout.id.desc()), response, limit, offset)
    actor = _actor(p)
    return [svc.rollout_out(db, r, actor) for r in rows]


@router.get("/rollouts/{rollout_id}")
def get_rollout(rollout_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    return svc.rollout_out(db, _get(db, rollout_id, p), _actor(p), detail=True)


@router.get("/rollouts/{rollout_id}/steps")
def steps(
    rollout_id: int,
    host_id: int | None = None,
    phase: Literal["dry_run", "execute"] | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Журнал команд: по хосту (host_id) или вся раскатка; stdout/stderr — как вернул хост."""
    r = _get(db, rollout_id, p)
    stmt = select(RolloutStep).where(RolloutStep.rollout_id == r.id)
    if host_id is not None:
        h = db.get(RolloutHost, host_id)
        if h is None or h.rollout_id != r.id:
            raise not_found("Хост раскатки")
        stmt = stmt.where(RolloutStep.rollout_host_id == host_id)
    if phase:
        stmt = stmt.where(RolloutStep.phase == phase)
    return [svc.step_out(s) for s in db.scalars(stmt.order_by(RolloutStep.id).limit(2000))]


def _act(db: Session, r: Rollout, p: Principal) -> dict:
    db.commit()
    db.refresh(r)
    return svc.rollout_out(db, r, _actor(p), detail=True)


@router.post("/rollouts/{rollout_id}/dry-run", status_code=202)
def dry_run(
    rollout_id: int, p: Principal = Depends(require(Perm.REMEDIATE_EXECUTE)), db: Session = Depends(get_db)
) -> dict:
    r = _get(db, rollout_id, p, lock=True)
    try:
        job = svc.request_dry_run(db, r, _actor(p))
    except RolloutError as e:
        raise _fail(db, e)
    db.commit()
    jobs.runner.submit(job.id)
    return _act(db, r, p)


@router.post("/rollouts/{rollout_id}/approve")
def approve(
    rollout_id: int,
    body: ApproveIn,
    p: Principal = Depends(require(Perm.ROLLOUT_APPROVE)),
    db: Session = Depends(get_db),
) -> dict:
    r = _get(db, rollout_id, p, lock=True)
    try:
        svc.approve(
            db,
            r,
            _actor(p),
            allow_reboot=body.allow_reboot,
            outside_window=body.outside_window,
            outside_window_reason=body.outside_window_reason,
            custom_ack=body.custom_ack,
            note=body.note,
        )
    except RolloutError as e:
        raise _fail(db, e)
    return _act(db, r, p)


@router.post("/rollouts/{rollout_id}/reject")
def reject(
    rollout_id: int,
    body: ReasonIn,
    p: Principal = Depends(require(Perm.ROLLOUT_APPROVE)),
    db: Session = Depends(get_db),
) -> dict:
    r = _get(db, rollout_id, p, lock=True)
    try:
        svc.reject(db, r, _actor(p), body.reason)
    except RolloutError as e:
        raise _fail(db, e)
    return _act(db, r, p)


@router.post("/rollouts/{rollout_id}/start", status_code=202)
def start(
    rollout_id: int, p: Principal = Depends(require(Perm.REMEDIATE_EXECUTE)), db: Session = Depends(get_db)
) -> dict:
    # Блокировка проекта: две раскатки одного проекта не стартуют одновременно.
    r = _get(db, rollout_id, p)
    db.scalars(select(Project).where(Project.id == r.project_id).with_for_update()).first()
    r = _get(db, rollout_id, p, lock=True)
    try:
        job = svc.start(db, r, _actor(p))
    except RolloutError as e:
        raise _fail(db, e)
    db.commit()
    jobs.runner.submit(job.id)
    return _act(db, r, p)


@router.post("/rollouts/{rollout_id}/stop")
def stop(
    rollout_id: int,
    body: ReasonIn,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """Аварийный стоп: новые хосты и перезагрузки не начинаются; идущая команда доходит до конца."""
    r = _get(db, rollout_id, p)
    try:
        svc.request_stop(db, r, _actor(p), body.reason)
    except RolloutError as e:
        raise _fail(db, e)
    return _act(db, r, p)


@router.post("/rollouts/{rollout_id}/cancel")
def cancel(
    rollout_id: int,
    body: OptionalReasonIn | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    r = _get(db, rollout_id, p, lock=True)
    try:
        svc.cancel(db, r, _actor(p), (body or OptionalReasonIn()).reason)
    except RolloutError as e:
        raise _fail(db, e)
    return _act(db, r, p)


@router.get("/projects/{project_id}/rollout-settings")
def get_settings_(project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    pr = get_project(db, project_id, p)
    return {"rollout_parallelism": pr.rollout_parallelism}


@router.put("/projects/{project_id}/rollout-settings")
def put_settings(
    project_id: str,
    body: SettingsIn,
    p: Principal = Depends(require(Perm.ROLLOUT_APPROVE)),
    db: Session = Depends(get_db),
) -> dict:
    """Сколько хостов проекта раскатка обрабатывает одновременно (руководитель)."""
    pr = get_project(db, project_id, p)
    old = pr.rollout_parallelism
    pr.rollout_parallelism = body.rollout_parallelism
    audit.record(
        db,
        p.user,
        "rollout.settings",
        object_type="project",
        object_id=pr.id,
        project_id=pr.id,
        ip=p.ip,
        details={"rollout_parallelism": {"from": old, "to": pr.rollout_parallelism}},
    )
    db.commit()
    return {"rollout_parallelism": pr.rollout_parallelism}
