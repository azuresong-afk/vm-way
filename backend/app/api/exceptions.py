"""Исключения (задача 2.5): оформить по заявке, утвердить или отклонить, отозвать, снять, продлить,
повторить отметку в «Сканере»; список для экрана «Исключения».

Права: смотрят все с `view`. Оформляет исполнитель заявки или руководитель (`ticket_work`).
Утверждает и отклоняет только названный утверждающий с `exception_approve`, не автор исключения.
Снимает руководитель или утверждающий, продлевает — `exception_approve`. Отказы — в журнал."""

from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.api.common import not_found, paginate
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import Ticket, TicketException
from app.rbac import Perm
from app.services import exceptions as svc
from app.services.workflow import Actor, WorkflowError

router = APIRouter(tags=["exceptions"])


def _actor(p: Principal) -> Actor:
    return Actor(user=p.user, perms=p.perms, ip=p.ip)


def _fail(db: Session, e: WorkflowError, p: Principal, action: str, ex_id=None, ticket_id=None, project_id=None):
    db.rollback()
    if e.code == 403:
        audit.record_separately(
            p.user,
            "exception.denied",
            object_type="exception" if ex_id else "ticket",
            object_id=ex_id or ticket_id,
            project_id=project_id,
            result="denied",
            ip=p.ip,
            details={"action": action, "exception_id": ex_id, "ticket_id": ticket_id, "error": e.message},
        )
    return HTTPException(e.code, e.message)


def _get(db: Session, exception_id: int, p: Principal) -> TicketException:
    ex = db.get(TicketException, exception_id)
    if ex is None:
        raise not_found("Исключение")
    get_project(db, ex.project_id, p)
    return ex


def _submit(job) -> None:
    if job is not None:
        jobs.runner.submit(job.id)


class ExceptionIn(BaseModel):
    kind: Literal["risk_accepted", "false_positive"]
    reason: str = Field(max_length=4000)
    measures: str = Field(default="", max_length=4000)
    approver_id: int | None = None
    review_on: date | None = None
    sync_scanner: bool = False


class NoteIn(BaseModel):
    note: str = Field(default="", max_length=2000)


class ReasonIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ExtendIn(BaseModel):
    review_on: date | None = None
    reason: str = Field(default="", max_length=2000)


@router.get("/projects/{project_id}/exception-meta")
def exception_meta(project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    """Для формы: кто может утверждать, доступна ли отметка в «Сканере», границы даты пересмотра."""
    get_project(db, project_id, p)
    today = svc.today()
    return {
        "approvers": [
            {"id": u.id, "username": u.username, "display_name": u.display_name or u.username}
            for u in svc.approvers(db)
            if u.id != p.user.id
        ],
        "sync_available": svc.sync_available(db, project_id),
        "today": today,
        "min_review_on": today + timedelta(days=1),
        "max_review_on": today + timedelta(days=svc.MAX_DAYS),
        "default_review_on": today + timedelta(days=90),
        "soon_days": svc.SOON_DAYS,
    }


@router.get("/projects/{project_id}/exceptions")
def list_exceptions(
    project_id: str,
    response: Response,
    state: Literal["all", "pending", "active", "review_soon", "ended", "to_approve"] = "all",
    kind: Literal["risk_accepted", "false_positive"] | None = None,
    ticket_id: int | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = 50,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(TicketException).join(Ticket, Ticket.id == TicketException.ticket_id)
    stmt = stmt.where(TicketException.project_id == project_id)
    stmt = _state_filter(stmt, state, p)
    if kind:
        stmt = stmt.where(TicketException.kind == kind)
    if ticket_id is not None:
        stmt = stmt.where(TicketException.ticket_id == ticket_id)
    if q and q.strip():
        text = q.strip().lstrip("№#")
        like = f"%{text}%"
        conds = [Ticket.title.ilike(like), TicketException.reason.ilike(like)]
        if text.isdigit():
            conds.append(Ticket.id == int(text))
        stmt = stmt.where(or_(*conds))
    if state in ("active", "review_soon"):
        stmt = stmt.order_by(TicketException.review_on.is_(None), TicketException.review_on, TicketException.id)
    else:
        stmt = stmt.order_by(TicketException.id.desc())
    actor = _actor(p)
    return [svc.exception_out(ex, db, actor) for ex in paginate(db, stmt, response, limit, offset)]


def _state_filter(stmt, state: str, p: Principal):
    if state == "pending":
        return stmt.where(TicketException.status == "pending")
    if state == "to_approve":
        return stmt.where(TicketException.status == "pending", TicketException.approver_id == p.user.id)
    if state == "active":
        return stmt.where(TicketException.status == "active")
    if state == "review_soon":
        return stmt.where(
            TicketException.status == "active",
            TicketException.review_on.is_not(None),
            TicketException.review_on <= svc.today() + timedelta(days=svc.SOON_DAYS),
        )
    if state == "ended":
        return stmt.where(TicketException.status.not_in(svc.OPEN))
    return stmt


@router.get("/projects/{project_id}/exception-counts")
def exception_counts(
    project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    get_project(db, project_id, p)
    out = {}
    for state in ("pending", "to_approve", "active", "review_soon", "ended", "all"):
        stmt = _state_filter(select(func.count(TicketException.id)), state, p)
        out[state] = db.scalar(stmt.where(TicketException.project_id == project_id)) or 0
    for kind in svc.KINDS:
        out[kind] = (
            db.scalar(
                select(func.count(TicketException.id)).where(
                    TicketException.project_id == project_id,
                    TicketException.kind == kind,
                    TicketException.status == "active",
                )
            )
            or 0
        )
    return out


@router.get("/exceptions/{exception_id}")
def read_exception(
    exception_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    return svc.exception_out(_get(db, exception_id, p), db, _actor(p))


@router.post("/tickets/{ticket_id}/exceptions", status_code=201)
def create_exception(
    ticket_id: int, body: ExceptionIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    t = db.scalars(select(Ticket).where(Ticket.id == ticket_id).with_for_update()).first()
    if t is None:
        raise not_found("Заявка")
    get_project(db, t.project_id, p)
    try:
        ex = svc.request(
            db,
            t,
            _actor(p),
            kind=body.kind,
            reason=body.reason,
            measures=body.measures,
            approver_id=body.approver_id,
            review_on=body.review_on,
            sync_scanner=body.sync_scanner,
        )
    except WorkflowError as e:
        raise _fail(db, e, p, "request", ticket_id=t.id, project_id=t.project_id)
    db.commit()
    db.refresh(ex)
    return svc.exception_out(ex, db, _actor(p))


def _act(db: Session, exception_id: int, p: Principal, action: str, fn) -> dict:
    ex = _get(db, exception_id, p)
    try:
        job = fn(ex)
    except WorkflowError as e:
        raise _fail(db, e, p, action, ex_id=ex.id, ticket_id=ex.ticket_id, project_id=ex.project_id)
    db.commit()
    _submit(job)
    db.refresh(ex)
    return svc.exception_out(ex, db, _actor(p))


@router.post("/exceptions/{exception_id}/approve")
def approve(
    exception_id: int,
    body: NoteIn | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    note = body.note if body else ""
    return _act(db, exception_id, p, "approve", lambda ex: svc.approve(db, ex, _actor(p), note))


@router.post("/exceptions/{exception_id}/reject")
def reject(
    exception_id: int, body: ReasonIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    return _act(db, exception_id, p, "reject", lambda ex: svc.reject(db, ex, _actor(p), body.reason))


@router.post("/exceptions/{exception_id}/withdraw")
def withdraw(
    exception_id: int,
    body: ReasonIn | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    reason = body.reason if body else ""
    return _act(db, exception_id, p, "withdraw", lambda ex: svc.withdraw(db, ex, _actor(p), reason))


@router.post("/exceptions/{exception_id}/revoke")
def revoke(
    exception_id: int, body: ReasonIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    return _act(db, exception_id, p, "revoke", lambda ex: svc.revoke(db, ex, _actor(p), body.reason))


@router.post("/exceptions/{exception_id}/extend")
def extend(
    exception_id: int, body: ExtendIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> dict:
    return _act(db, exception_id, p, "extend", lambda ex: svc.extend(db, ex, _actor(p), body.review_on, body.reason))


@router.post("/exceptions/{exception_id}/sync", status_code=202)
def sync(exception_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    return _act(db, exception_id, p, "sync", lambda ex: svc.request_sync(db, ex, _actor(p)))
