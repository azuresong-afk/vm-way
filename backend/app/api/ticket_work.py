"""Работа с заявкой (задача 1.5): взять, назначить, перевести, переопределить уровень,
комментировать, наблюдать, массовые действия. Повторная проверка — задача 1.6."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.api.common import not_found
from app.api.tickets import _counts, ticket_brief
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import Ticket, Verification
from app.rbac import Perm
from app.services import verification, workflow
from app.services.workflow import Actor, WorkflowError

router = APIRouter(tags=["tickets"])


def _actor(p: Principal) -> Actor:
    return Actor(user=p.user, perms=p.perms, ip=p.ip)


def _locked(db: Session, ticket_id: int, p: Principal) -> Ticket:
    """Заявка под блокировкой строки: два одновременных изменения не перетрут друг друга."""
    t = db.scalars(select(Ticket).where(Ticket.id == ticket_id).with_for_update()).first()
    if not t:
        raise not_found("Заявка")
    get_project(db, t.project_id, p)
    return t


def _fail(e: WorkflowError, db: Session) -> HTTPException:
    db.rollback()
    return HTTPException(e.code, e.message)


def _out(db: Session, t: Ticket) -> dict:
    db.refresh(t)
    return ticket_brief(t, _counts(db, [t.id]))


class AssignIn(BaseModel):
    assignee_id: int | None


class StatusIn(BaseModel):
    status: str = Field(max_length=32)
    reason: str | None = Field(default=None, max_length=2000)


class OverrideIn(BaseModel):
    severity: str | None = Field(default=None, max_length=16)
    priority: str | None = Field(default=None, max_length=64)
    reason: str = Field(max_length=2000)


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class WatchIn(BaseModel):
    watch: bool = True


@router.post("/tickets/{ticket_id}/take")
def take(ticket_id: int, p: Principal = Depends(require(Perm.TICKET_WORK)), db: Session = Depends(get_db)) -> dict:
    t = _locked(db, ticket_id, p)
    try:
        workflow.take(db, t, _actor(p))
    except WorkflowError as e:
        raise _fail(e, db)
    db.commit()
    return _out(db, t)


@router.post("/tickets/{ticket_id}/assign")
def assign(
    ticket_id: int, body: AssignIn, p: Principal = Depends(require(Perm.TICKET_ASSIGN)), db: Session = Depends(get_db)
) -> dict:
    t = _locked(db, ticket_id, p)
    try:
        workflow.assign(db, t, _actor(p), body.assignee_id)
    except WorkflowError as e:
        raise _fail(e, db)
    db.commit()
    return _out(db, t)


@router.post("/tickets/{ticket_id}/status")
def change_status(
    ticket_id: int, body: StatusIn, p: Principal = Depends(require(Perm.TICKET_WORK)), db: Session = Depends(get_db)
) -> dict:
    t = _locked(db, ticket_id, p)
    try:
        workflow.change_status(db, t, _actor(p), body.status, body.reason)
    except WorkflowError as e:
        if e.code == 403:
            audit.record_separately(
                p.user,
                "ticket.status",
                object_type="ticket",
                object_id=t.id,
                project_id=t.project_id,
                result="denied",
                ip=p.ip,
                details={"ticket_id": t.id, "from": t.status, "to": body.status},
            )
        raise _fail(e, db)
    db.commit()
    return _out(db, t)


@router.post("/tickets/{ticket_id}/override")
def override(
    ticket_id: int,
    body: OverrideIn,
    p: Principal = Depends(require(Perm.TICKET_OVERRIDE)),
    db: Session = Depends(get_db),
) -> dict:
    t = _locked(db, ticket_id, p)
    try:
        workflow.override(db, t, _actor(p), severity=body.severity, priority=body.priority, reason=body.reason)
    except WorkflowError as e:
        raise _fail(e, db)
    db.commit()
    return _out(db, t)


@router.post("/tickets/{ticket_id}/comments", status_code=201)
def add_comment(
    ticket_id: int, body: CommentIn, p: Principal = Depends(require(Perm.TICKET_WORK)), db: Session = Depends(get_db)
) -> dict:
    t = _locked(db, ticket_id, p)
    try:
        c = workflow.add_comment(db, t, _actor(p), body.body)
    except WorkflowError as e:
        raise _fail(e, db)
    db.commit()
    u = p.user
    return {
        "id": c.id,
        "at": c.created_at,
        "author": {"id": u.id, "username": u.username, "display_name": u.display_name or u.username},
        "kind": c.kind,
        "body": c.body,
        "data": c.data,
    }


@router.post("/tickets/{ticket_id}/watch")
def watch(
    ticket_id: int,
    body: WatchIn | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """Наблюдать за заявкой. Выбор: доступно и наблюдателю (`viewer`) — подписка ничего не меняет в работе."""
    t = _locked(db, ticket_id, p)
    on = True if body is None else body.watch
    workflow.set_watch(db, t, _actor(p), on)
    db.commit()
    return {"ticket_id": t.id, "watching": on}


class VerifyIn(BaseModel):
    hosts: list[str] | None = Field(default=None, max_length=1024)
    # «Исправлено — проверить»: перевести заявку в «Исправлено», если это разрешено пользователю.
    mark_fixed: bool = True


@router.post("/tickets/{ticket_id}/verify", status_code=202)
def verify(
    ticket_id: int,
    body: VerifyIn | None = None,
    p: Principal = Depends(require(Perm.VERIFY)),
    db: Session = Depends(get_db),
) -> dict:
    """Повторная проверка прицельным прогоном «Сканера». Итог применяет фоновая задача."""
    body = body or VerifyIn()
    t = _locked(db, ticket_id, p)
    try:
        items = verification.request(db, t, _actor(p), body.hosts, mark_fixed=body.mark_fixed)
    except WorkflowError as e:
        raise _fail(e, db)
    db.commit()
    for v in items:
        jobs.runner.submit(v.result["job_id"])
    for v in items:
        db.refresh(v)
    return {"ticket": _out(db, t), "verifications": [verification.verification_out(v) for v in items]}


@router.get("/tickets/{ticket_id}/verifications")
def ticket_verifications(
    ticket_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    t = db.get(Ticket, ticket_id)
    if not t:
        raise not_found("Заявка")
    get_project(db, t.project_id, p)
    rows = db.scalars(select(Verification).where(Verification.ticket_id == t.id).order_by(Verification.id.desc()))
    return [verification.verification_out(v) for v in rows]


@router.get("/verifications/{verification_id}")
def read_verification(
    verification_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    v = db.get(Verification, verification_id)
    if not v:
        raise not_found("Проверка")
    get_project(db, v.project_id, p)
    return verification.verification_out(v)


class BulkIn(BaseModel):
    ticket_ids: list[int] = Field(min_length=1, max_length=500)
    action: Literal["assign", "status"]
    assignee_id: int | None = None
    status: str | None = Field(default=None, max_length=32)
    reason: str | None = Field(default=None, max_length=2000)


@router.post("/projects/{project_id}/tickets/bulk")
def bulk(
    project_id: str,
    body: BulkIn,
    p: Principal = Depends(require(Perm.TICKET_ASSIGN)),
    db: Session = Depends(get_db),
) -> dict:
    """Массовые действия: назначить (или снять) исполнителя, перевести в статус.

    Каждая заявка проверяется отдельно: подходящие меняются, по остальным — причина отказа.
    Всё — одной транзакцией, каждая изменённая заявка — своей записью в журнале."""
    get_project(db, project_id, p)
    if body.action == "status" and not body.status:
        raise HTTPException(422, "Укажите статус")
    ids = list(dict.fromkeys(body.ticket_ids))
    found = {
        t.id: t
        for t in db.scalars(select(Ticket).where(Ticket.id.in_(ids), Ticket.project_id == project_id).with_for_update())
    }
    actor = _actor(p)
    done: list[int] = []
    unchanged: list[int] = []
    failed: list[dict] = []
    for tid in ids:
        t = found.get(tid)
        if t is None:
            failed.append({"id": tid, "error": "Заявка не найдена в проекте"})
            continue
        # Проверки в workflow идут до любых изменений: отказ по одной заявке ничего в ней не трогает.
        try:
            if body.action == "assign":
                changed = workflow.assign(db, t, actor, body.assignee_id, via="bulk")
            else:
                workflow.change_status(db, t, actor, body.status or "", body.reason)
                changed = True
        except WorkflowError as e:
            failed.append({"id": tid, "error": e.message})
            continue
        (done if changed else unchanged).append(tid)
    audit.record(
        db,
        p.user,
        "ticket.bulk",
        object_type="project",
        object_id=project_id,
        project_id=project_id,
        ip=p.ip,
        result="ok" if not failed else ("partial" if done else "failed"),
        details={
            "action": body.action,
            "assignee_id": body.assignee_id,
            "status": body.status,
            "requested": len(ids),
            "changed": done,
            "failed": [f["id"] for f in failed],
        },
    )
    db.commit()
    return {"changed": done, "unchanged": unchanged, "failed": failed}
