"""Заявки и уязвимости: списки с фильтрами и карточки (чтение). Изменение заявок — app/api/ticket_work.py."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.common import not_found, paginate
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import (
    Comment,
    ScanRun,
    Ticket,
    TicketHistory,
    TicketHost,
    User,
    Verification,
    Vulnerability,
    VulnerabilityEvent,
)
from app.rbac import Perm
from app.services.verification import verification_out
from app.services.workflow import CLOSED_STATUSES, SEVERITIES, STATUSES, Actor, allowed_targets, watchers

router = APIRouter(tags=["tickets"])

OPEN_STATUSES = [s for s in STATUSES if s not in CLOSED_STATUSES]

_SEV_RANK = case(
    {s: i for i, s in enumerate(SEVERITIES)}, value=func.coalesce(Ticket.severity_override, Ticket.severity), else_=9
)


def _user(u: User | None) -> dict | None:
    return {"id": u.id, "username": u.username, "display_name": u.display_name or u.username} if u else None


def ticket_brief(t: Ticket, counts: dict[int, dict]) -> dict:
    c = counts.get(t.id, {})
    return {
        "id": t.id,
        "project_id": t.project_id,
        "title": t.title,
        "kind": t.kind,
        "scanner_kind": t.scanner_kind,
        "os": t.os,
        "os_family": t.os_family,
        "severity": t.effective_severity,
        "scanner_severity": t.severity,
        "severity_overridden": t.severity_override is not None,
        "priority": {"rank": t.priority_rank, "label": t.priority_override or t.priority_label},
        "status": t.status,
        "status_label": STATUSES.get(t.status, t.status),
        "is_regression": t.is_regression,
        "assignee": _user(t.assignee),
        "reboot": bool((t.action or {}).get("reboot")),
        "hosts_total": c.get("hosts", 0),
        "hosts_confirmed": c.get("confirmed", 0),
        "vulns_open": c.get("vulns_open", 0),
        "vulns_total": c.get("vulns", 0),
        "cves": (t.action or {}).get("cves", [])[:20],
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "closed_at": t.closed_at,
    }


def _counts(db: Session, ids: list[int]) -> dict[int, dict]:
    out: dict[int, dict] = {i: {} for i in ids}
    if not ids:
        return out
    for tid, total, confirmed in db.execute(
        select(TicketHost.ticket_id, func.count(), func.sum(case((TicketHost.status == "confirmed", 1), else_=0)))
        .where(TicketHost.ticket_id.in_(ids))
        .group_by(TicketHost.ticket_id)
    ):
        out[tid].update(hosts=total, confirmed=int(confirmed or 0))
    for tid, total, open_ in db.execute(
        select(Vulnerability.ticket_id, func.count(), func.sum(case((Vulnerability.state == "open", 1), else_=0)))
        .where(Vulnerability.ticket_id.in_(ids))
        .group_by(Vulnerability.ticket_id)
    ):
        out[tid].update(vulns=total, vulns_open=int(open_ or 0))
    return out


@router.get("/ticket-meta")
def ticket_meta(_: Principal = Depends(require(Perm.VIEW))) -> dict:
    from app.services.mirror import KIND_LABELS

    return {
        "statuses": [{"id": k, "label": v, "open": k in OPEN_STATUSES} for k, v in STATUSES.items()],
        "kinds": [{"id": k, "label": v} for k, v in KIND_LABELS.items()],
        "severities": SEVERITIES,
    }


@router.get("/projects/{project_id}/ticket-facets")
def ticket_facets(project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    """Значения для фильтров «Заявок»: ОС и виды, которые есть в проекте, с числом открытых заявок."""
    get_project(db, project_id, p)
    is_open = func.sum(case((Ticket.status.in_(OPEN_STATUSES), 1), else_=0))
    os_rows = db.execute(
        select(Ticket.os, func.count(), is_open)
        .where(Ticket.project_id == project_id, Ticket.os != "")
        .group_by(Ticket.os)
        .order_by(Ticket.os)
    ).all()
    kind_rows = db.execute(
        select(Ticket.kind, func.count(), is_open).where(Ticket.project_id == project_id).group_by(Ticket.kind)
    ).all()
    return {
        "os": [{"id": o, "total": n, "open": int(k or 0)} for o, n, k in os_rows],
        "kinds": [{"id": o, "total": n, "open": int(k or 0)} for o, n, k in sorted(kind_rows)],
    }


@router.get("/projects/{project_id}/tickets")
def list_tickets(
    project_id: str,
    response: Response,
    status: list[str] | None = Query(default=None),
    state: str | None = Query(default=None, pattern="^(open|closed)$"),
    severity: list[str] | None = Query(default=None),
    kind: list[str] | None = Query(default=None),
    os: list[str] | None = Query(default=None),
    assignee: str | None = None,
    host: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="priority", pattern="^(priority|severity|created|updated|title|hosts)$"),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
    limit: int = 50,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(Ticket).where(Ticket.project_id == project_id).options(selectinload(Ticket.assignee))
    if status:
        stmt = stmt.where(Ticket.status.in_(status))
    if state == "open":
        stmt = stmt.where(Ticket.status.in_(OPEN_STATUSES))
    elif state == "closed":
        stmt = stmt.where(Ticket.status.not_in(OPEN_STATUSES))
    if severity:
        stmt = stmt.where(func.coalesce(Ticket.severity_override, Ticket.severity).in_(severity))
    if kind:
        stmt = stmt.where(Ticket.kind.in_(kind))
    if os:
        stmt = stmt.where(Ticket.os.in_(os))
    if assignee == "me":
        stmt = stmt.where(Ticket.assignee_id == p.user.id)
    elif assignee == "none":
        stmt = stmt.where(Ticket.assignee_id.is_(None))
    elif assignee:
        if not assignee.isdigit():
            raise HTTPException(422, "assignee: id пользователя, me или none")
        stmt = stmt.where(Ticket.assignee_id == int(assignee))
    if host:
        stmt = stmt.where(Ticket.id.in_(select(TicketHost.ticket_id).where(TicketHost.host == host.strip())))
    if q and q.strip():
        like = f"%{q.strip()}%"
        num = q.strip().lstrip("№#").strip()
        conds = [
            Ticket.title.ilike(like),
            Ticket.id.in_(
                select(Vulnerability.ticket_id).where(
                    Vulnerability.project_id == project_id,
                    or_(Vulnerability.vuln_id.ilike(like), Vulnerability.host.ilike(like)),
                )
            ),
        ]
        if num.isdigit():
            conds.append(Ticket.id == int(num))
        stmt = stmt.where(or_(*conds))
    hosts_count = (
        select(func.count())
        .select_from(TicketHost)
        .where(TicketHost.ticket_id == Ticket.id)
        .correlate(Ticket)
        .scalar_subquery()
    )
    keys = {
        "priority": [func.coalesce(Ticket.priority_rank, 1_000_000), _SEV_RANK],
        "severity": [_SEV_RANK, func.coalesce(Ticket.priority_rank, 1_000_000)],
        "created": [Ticket.created_at],
        "updated": [Ticket.updated_at],
        "title": [Ticket.title],
        "hosts": [hosts_count],
    }[sort]
    keys = [k.desc() if order == "desc" else k.asc() for k in keys] + [Ticket.id.asc()]
    rows = paginate(db, stmt.order_by(*keys), response, limit, offset)
    counts = _counts(db, [t.id for t in rows])
    return [ticket_brief(t, counts) for t in rows]


def _get_ticket(db: Session, ticket_id: int, p: Principal) -> Ticket:
    t = db.get(Ticket, ticket_id)
    if not t:
        raise not_found("Заявка")
    get_project(db, t.project_id, p)
    return t


def vuln_out(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "dedup_key": v.dedup_key,
        "host": v.host,
        "port": v.port,
        "module": v.module,
        "finding_type": v.finding_type,
        "title": v.title,
        "severity": v.severity,
        "priority": v.priority,
        "vuln_id": v.vuln_id,
        "cve_ids": v.cve_ids,
        "bdu_ids": v.bdu_ids,
        "cvss": v.cvss,
        "software": v.software,
        "software_version": v.software_version,
        "confidence": v.confidence,
        "state": v.state,
        "is_regression": v.is_regression,
        "ticket_id": v.ticket_id,
        "scanner_finding_id": v.scanner_finding_id,
        "first_seen_at": v.first_seen_at,
        "last_seen_at": v.last_seen_at,
        "fixed_at": v.fixed_at,
    }


@router.get("/tickets/{ticket_id}")
def read_ticket(ticket_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    t = _get_ticket(db, ticket_id, p)
    counts = _counts(db, [t.id])
    vulns = list(
        db.scalars(
            select(Vulnerability)
            .where(Vulnerability.ticket_id == t.id)
            .order_by(Vulnerability.host, Vulnerability.vuln_id)
        )
    )
    by_host: dict[str, list[int]] = {}
    for v in vulns:
        by_host.setdefault(v.host, []).append(v.id)
    run_ids = {h.last_check_run_id for h in t.hosts if h.last_check_run_id}
    runs = {r.id: r for r in db.scalars(select(ScanRun).where(ScanRun.id.in_(run_ids)))} if run_ids else {}
    ws = watchers(db, t)
    checks = list(
        db.scalars(select(Verification).where(Verification.ticket_id == t.id).order_by(Verification.id.desc()).limit(5))
    )
    return {
        **ticket_brief(t, counts),
        "fix_key": t.fix_key,
        "action": t.action,
        "override_reason": t.override_reason,
        "evidence": t.evidence,
        "hosts": [
            {
                "id": h.id,
                "host": h.host,
                "installed": h.installed,
                "note": h.note,
                "status": h.status,
                "reason": h.reason,
                "vulnerability_ids": by_host.get(h.host, []),
                "last_check": (
                    {
                        "run_id": h.last_check_run_id,
                        "scanner_run_id": runs[h.last_check_run_id].scanner_run_id,
                        "finished_at": runs[h.last_check_run_id].finished_at,
                    }
                    if h.last_check_run_id in runs
                    else None
                ),
                "updated_at": h.updated_at,
            }
            for h in t.hosts
        ],
        "vulnerabilities": [vuln_out(v) for v in vulns],
        "watchers": [_user(u) for u in ws],
        "watching": any(u.id == p.user.id for u in ws),
        "verifications": [verification_out(v) for v in checks],
        "can": _can(t, p, verifying=any(v.status in ("requested", "running") for v in checks)),
    }


def _can(t: Ticket, p: Principal, verifying: bool = False) -> dict:
    """Что текущий пользователь может сделать с заявкой — для кнопок в карточке."""
    closed = t.status in CLOSED_STATUSES
    return {
        "statuses": allowed_targets(t, Actor(p.user, p.perms)),
        "take": p.can(Perm.TICKET_WORK) and not closed and t.assignee_id is None,
        "assign": p.can(Perm.TICKET_ASSIGN) and not closed,
        "override": p.can(Perm.TICKET_OVERRIDE),
        "comment": p.can(Perm.TICKET_WORK),
        "verify": p.can(Perm.VERIFY) and not closed and not verifying,
    }


@router.get("/tickets/{ticket_id}/history")
def ticket_history(ticket_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    t = _get_ticket(db, ticket_id, p)
    hist = db.scalars(select(TicketHistory).where(TicketHistory.ticket_id == t.id).order_by(TicketHistory.id))
    comments = db.scalars(select(Comment).where(Comment.ticket_id == t.id).order_by(Comment.id))
    return {
        "history": [
            {
                "id": h.id,
                "at": h.at,
                "actor": _user(h.actor),
                "action": h.action,
                "from": h.from_value,
                "to": h.to_value,
                "details": h.details,
            }
            for h in hist
        ],
        "comments": [
            {"id": c.id, "at": c.created_at, "author": _user(c.author), "kind": c.kind, "body": c.body, "data": c.data}
            for c in comments
        ],
    }


@router.get("/projects/{project_id}/vulnerabilities")
def list_vulnerabilities(
    project_id: str,
    response: Response,
    state: str | None = Query(default=None, pattern="^(open|fixed)$"),
    severity: list[str] | None = Query(default=None),
    host: str | None = None,
    ticket_id: int | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = 50,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(Vulnerability).where(Vulnerability.project_id == project_id)
    if state:
        stmt = stmt.where(Vulnerability.state == state)
    if severity:
        stmt = stmt.where(Vulnerability.severity.in_(severity))
    if host:
        stmt = stmt.where(Vulnerability.host == host.strip())
    if ticket_id is not None:
        stmt = stmt.where(Vulnerability.ticket_id == ticket_id)
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(Vulnerability.vuln_id.ilike(like), Vulnerability.title.ilike(like), Vulnerability.software.ilike(like))
        )
    sev = case({s: i for i, s in enumerate(SEVERITIES)}, value=Vulnerability.severity, else_=9)
    stmt = stmt.order_by(sev, Vulnerability.host, Vulnerability.id)
    return [vuln_out(v) for v in paginate(db, stmt, response, limit, offset)]


@router.get("/vulnerabilities/{vuln_id}")
def read_vulnerability(vuln_id: int, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise not_found("Уязвимость")
    get_project(db, v.project_id, p)
    events = db.execute(
        select(VulnerabilityEvent, ScanRun)
        .outerjoin(ScanRun, ScanRun.id == VulnerabilityEvent.run_id)
        .where(VulnerabilityEvent.vulnerability_id == v.id)
        .order_by(VulnerabilityEvent.id)
    ).all()
    return {
        **vuln_out(v),
        "events": [
            {
                "event": e.event,
                "at": e.at,
                "run_id": e.run_id,
                "scanner_run_id": r.scanner_run_id if r else None,
                "run_name": r.name if r else None,
            }
            for e, r in events
        ],
    }
