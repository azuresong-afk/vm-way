"""Окна обслуживания и план (задача 2.1): окна проекта, календарь дат, план даты окна,
постановка заявки в окно."""

from datetime import date, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app.api.common import not_found
from app.api.ticket_work import _actor, _fail, _locked, _out
from app.db import as_utc, get_db, utcnow
from app.deps import Principal, get_project, require
from app.models import MaintenanceWindow, Ticket
from app.rbac import Perm
from app.services import windows as svc
from app.services.windows import DEFAULT_TZ, WindowError
from app.services.workflow import CLOSED_STATUSES, WorkflowError

router = APIRouter(tags=["windows"])

MAX_CALENDAR_DAYS = 92


class WindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: Literal["once", "recurring", "blackout"]
    timezone: str = Field(default=DEFAULT_TZ, max_length=64)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    weekdays: list[int] = Field(default_factory=list, max_length=7)
    start_time: str = Field(default="", max_length=5)
    duration_minutes: int = Field(default=0, ge=0)
    valid_from: date | None = None
    valid_until: date | None = None
    hosts: list[str] = Field(default_factory=list, max_length=2000)
    groups: list[str] = Field(default_factory=list, max_length=100)
    note: str = Field(default="", max_length=2000)
    is_active: bool = True


class WindowPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    timezone: str | None = Field(default=None, max_length=64)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    weekdays: list[int] | None = Field(default=None, max_length=7)
    start_time: str | None = Field(default=None, max_length=5)
    duration_minutes: int | None = Field(default=None, ge=0)
    valid_from: date | None = None
    valid_until: date | None = None
    hosts: list[str] | None = Field(default=None, max_length=2000)
    groups: list[str] | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=2000)
    is_active: bool | None = None


def _get(db: Session, window_id: int, p: Principal, *, lock: bool = False) -> MaintenanceWindow:
    stmt = select(MaintenanceWindow).where(MaintenanceWindow.id == window_id)
    w = db.scalars(stmt.with_for_update() if lock else stmt).first()
    if not w:
        raise not_found("Окно")
    get_project(db, w.project_id, p)
    return w


def _ticket_counts(db: Session, project_id: str) -> dict[int, int]:
    return dict(
        db.execute(
            select(Ticket.window_id, func.count())
            .where(Ticket.project_id == project_id, Ticket.window_id.is_not(None))
            .where(Ticket.status.not_in(CLOSED_STATUSES))
            .group_by(Ticket.window_id)
        ).all()
    )


def _snapshot(w: MaintenanceWindow) -> dict:
    return {
        "name": w.name,
        "kind": w.kind,
        "schedule": svc.schedule_text(w),
        "hosts": len(w.hosts or []),
        "groups": w.groups or [],
        "is_active": w.is_active,
    }


@router.get("/projects/{project_id}/windows")
def list_windows(
    project_id: str,
    include_inactive: bool = True,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    now = utcnow()
    counts = _ticket_counts(db, project_id)
    return [
        svc.window_out(db, w, now, counts)
        for w in svc.project_windows(db, project_id, active_only=not include_inactive)
    ]


@router.post("/projects/{project_id}/windows", status_code=201)
def create_window(
    project_id: str,
    body: WindowIn,
    p: Principal = Depends(require(Perm.WINDOWS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    get_project(db, project_id, p)
    w = MaintenanceWindow(project_id=project_id, created_by=p.user.id, **body.model_dump())
    w.name = w.name.strip()
    try:
        svc.validate(w)
    except WindowError as e:
        raise HTTPException(e.code, e.message)
    db.add(w)
    db.flush()
    audit.record(
        db,
        p.user,
        "window.create",
        object_type="window",
        object_id=w.id,
        project_id=project_id,
        ip=p.ip,
        details=_snapshot(w),
    )
    db.commit()
    return svc.window_out(db, w, utcnow())


@router.get("/windows/{window_id}")
def read_window(window_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    w = _get(db, window_id, p)
    return svc.window_out(db, w, utcnow(), _ticket_counts(db, w.project_id))


@router.patch("/windows/{window_id}")
def update_window(
    window_id: int,
    body: WindowPatch,
    p: Principal = Depends(require(Perm.WINDOWS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    w = _get(db, window_id, p, lock=True)
    before = _snapshot(w)
    for k, v in body.model_dump(exclude_unset=True).items():
        if v is None and k in (
            "name",
            "timezone",
            "weekdays",
            "start_time",
            "duration_minutes",
            "hosts",
            "groups",
            "note",
        ):
            continue
        setattr(w, k, v.strip() if k == "name" else v)
    try:
        svc.validate(w)
    except WindowError as e:
        db.rollback()
        raise HTTPException(e.code, e.message)
    w.updated_at = utcnow()
    audit.record(
        db,
        p.user,
        "window.update",
        object_type="window",
        object_id=w.id,
        project_id=w.project_id,
        ip=p.ip,
        details={"before": before, "after": _snapshot(w)},
    )
    db.commit()
    return svc.window_out(db, w, utcnow(), _ticket_counts(db, w.project_id))


@router.delete("/windows/{window_id}", status_code=204)
def delete_window(
    window_id: int, p: Principal = Depends(require(Perm.WINDOWS_MANAGE)), db: Session = Depends(get_db)
) -> None:
    """Удалить окно можно, только если в нём нет открытых заявок; иначе — снять заявки или отключить окно."""
    w = _get(db, window_id, p, lock=True)
    busy = _ticket_counts(db, w.project_id).get(w.id, 0)
    if busy:
        raise HTTPException(409, f"В окне {busy} открытых заявок: снимите их с окна или отключите окно")
    # Закрытые заявки помнят окно только для истории — отвязываем их.
    db.execute(update(Ticket).where(Ticket.window_id == w.id).values(window_id=None))
    audit.record(
        db,
        p.user,
        "window.delete",
        object_type="window",
        object_id=w.id,
        project_id=w.project_id,
        ip=p.ip,
        details=_snapshot(w),
    )
    db.delete(w)
    db.commit()


def _range(start: datetime | None, end: datetime | None, default_days: int) -> tuple[datetime, datetime]:
    start = as_utc(start) if start else utcnow()
    end = as_utc(end) if end else start + timedelta(days=default_days)
    if end <= start:
        raise HTTPException(422, "Конец диапазона раньше начала")
    if end - start > timedelta(days=MAX_CALENDAR_DAYS):
        raise HTTPException(422, f"Диапазон — не больше {MAX_CALENDAR_DAYS} дней")
    return start, end


@router.get("/projects/{project_id}/calendar")
def calendar(
    project_id: str,
    start: AwareDatetime | None = Query(default=None, alias="from"),
    end: AwareDatetime | None = Query(default=None, alias="to"),
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """Даты окон и блэкаутов в диапазоне (по умолчанию — 4 недели вперёд) с итогом по каждой."""
    get_project(db, project_id, p)
    start, end = _range(start, end, 28)
    ws = svc.project_windows(db, project_id)
    occ = svc.occurrences(ws, start, end, include_blackouts=True, scopes=svc.scopes_for(db, ws))
    items = []
    for o in occ:
        row = o.out()
        if o.window.kind != "blackout":
            pl = svc.plan(db, o)
            row.update(tickets=len(pl["items"]), will_close=0 if o.cancelled else pl["will_close"])
        items.append(row)
    return {"from": start, "to": end, "items": items}


@router.get("/windows/{window_id}/plan")
def window_plan(
    window_id: int,
    at: AwareDatetime | None = None,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """План даты окна. `at` — момент внутри нужной даты или до неё (по умолчанию — сейчас):
    берётся текущая или ближайшая дата, в том числе выпавшая из-за блэкаута."""
    w = _get(db, window_id, p)
    if w.kind == "blackout":
        raise HTTPException(422, "У блэкаута нет плана работ")
    at = as_utc(at) if at else utcnow()
    occ = svc.next_occurrence(db, w, at, horizon_days=400, usable=False)
    if occ is None:
        return {"window": svc.window_out(db, w, utcnow()), "plan": None, "prev": None, "next": None}
    prev = [o for o in svc.window_occurrences(db, w, occ.start - timedelta(days=60), occ.start) if o.start < occ.start]
    nxt = svc.next_occurrence(db, w, occ.end, horizon_days=400, usable=False)
    return {
        "window": svc.window_out(db, w, utcnow(), _ticket_counts(db, w.project_id)),
        "plan": svc.plan(db, occ),
        "prev": prev[-1].start if prev else None,
        "next": nxt.start if nxt and nxt.start > occ.start else None,
    }


class PlaceIn(BaseModel):
    window_id: int | None


@router.post("/tickets/{ticket_id}/window")
def place_ticket(
    ticket_id: int, body: PlaceIn, p: Principal = Depends(require(Perm.TICKET_WORK)), db: Session = Depends(get_db)
) -> dict:
    """Поставить заявку в окно или снять с окна (`window_id: null`)."""
    t = _locked(db, ticket_id, p)
    w = None
    if body.window_id is not None:
        w = db.get(MaintenanceWindow, body.window_id)
        if w is None or w.project_id != t.project_id:
            db.rollback()
            raise not_found("Окно")
    try:
        svc.place(db, t, _actor(p), w)
    except WorkflowError as e:
        if e.code == 403:
            audit.record_separately(
                p.user,
                "ticket.window",
                object_type="ticket",
                object_id=t.id,
                project_id=t.project_id,
                result="denied",
                ip=p.ip,
                details={"ticket_id": t.id, "to": body.window_id},
            )
        raise _fail(e, db)
    db.commit()
    return _out(db, t)
