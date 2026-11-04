"""Журнал аудита: просмотр и выгрузка."""

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import audit
from app.api.common import paginate
from app.db import get_db
from app.deps import Principal, require
from app.models import AuditLog
from app.rbac import Perm

router = APIRouter(tags=["audit"])


def _filtered(
    action: str | None,
    user: str | None,
    project: str | None,
    result: str | None,
    since: datetime | None,
    until: datetime | None,
    q: str | None,
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if user:
        stmt = stmt.where(AuditLog.username == user)
    if project:
        stmt = stmt.where(AuditLog.project_id == project)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if since:
        stmt = stmt.where(AuditLog.at >= since)
    if until:
        stmt = stmt.where(AuditLog.at <= until)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(AuditLog.object_id.like(like), AuditLog.action.like(like), AuditLog.username.like(like)))
    return stmt


def entry_out(e: AuditLog) -> dict:
    return {
        "id": e.id,
        "at": e.at,
        "user_id": e.user_id,
        "user_sub": e.user_sub,
        "username": e.username,
        "product": e.product,
        "action": e.action,
        "object_type": e.object_type,
        "object_id": e.object_id,
        "project_id": e.project_id,
        "result": e.result,
        "ip": e.ip,
        "details": e.details,
    }


@router.get("/audit")
def list_audit(
    response: Response,
    limit: int = 50,
    offset: int = 0,
    action: str | None = None,
    user: str | None = None,
    project: str | None = None,
    result: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = None,
    p: Principal = Depends(require(Perm.AUDIT_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    stmt = _filtered(action, user, project, result, since, until, q)
    return [entry_out(e) for e in paginate(db, stmt, response, limit, offset)]


@router.get("/audit/export")
def export_audit(
    action: str | None = None,
    user: str | None = None,
    project: str | None = None,
    result: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = None,
    p: Principal = Depends(require(Perm.AUDIT_VIEW)),
    db: Session = Depends(get_db),
) -> Response:
    rows = db.scalars(_filtered(action, user, project, result, since, until, q).limit(100_000))
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["id", "время (UTC)", "пользователь", "действие", "объект", "id объекта", "проект", "результат", "IP"])
    for e in rows:
        w.writerow(
            [
                e.id,
                e.at.isoformat(),
                e.username,
                e.action,
                e.object_type,
                e.object_id,
                e.project_id or "",
                e.result,
                e.ip,
            ]
        )
    audit.record(db, p.user, "audit.export", object_type="audit", ip=p.ip)
    db.commit()
    return Response(
        "﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vm-audit.csv"'},
    )
