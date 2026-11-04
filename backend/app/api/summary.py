"""Сводка проекта и быстрый поиск (задача 1.7): данные для экрана «Сводка» и палитры Ctrl+K."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import as_utc, get_db, utcnow
from app.deps import Principal, get_project, require
from app.models import Project, ScanRun, Ticket, TicketHost, Vulnerability
from app.rbac import Perm
from app.services.workflow import CLOSED_STATUSES, SEVERITIES, STATUSES

router = APIRouter(tags=["summary"])

OPEN_STATUSES = [s for s in STATUSES if s not in CLOSED_STATUSES]
PERIOD_WEEKS = {"3m": 13, "1y": 52}


def _week_start(d: datetime) -> datetime:
    d = d.astimezone(UTC)
    return datetime(d.year, d.month, d.day, tzinfo=UTC) - timedelta(days=d.weekday())


def _sev_zero() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}


@router.get("/projects/{project_id}/summary")
def summary(
    project_id: str,
    period: str = Query(default="3m", pattern="^(3m|1y)$"),
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """Сводка: открытые заявки и уязвимости, изменение за период, недели «появилось / закрыто»
    по уровням, среднее время устранения, топ хостов и последние подтверждения.

    Выбор: недели и время устранения считаются по уязвимостям (`first_seen_at` — дата прогона,
    который её нашёл; `fixed_at` — дата прогона, который подтвердил исправление), а не по заявкам:
    заявка может объединять уязвимости, найденные в разное время."""
    get_project(db, project_id, p)
    now = utcnow()
    weeks = PERIOD_WEEKS[period]
    first_week = _week_start(now) - timedelta(weeks=weeks - 1)

    vulns = db.execute(
        select(
            Vulnerability.host,
            Vulnerability.severity,
            Vulnerability.state,
            Vulnerability.first_seen_at,
            Vulnerability.fixed_at,
            Vulnerability.ticket_id,
        ).where(Vulnerability.project_id == project_id)
    ).all()

    open_by_sev = _sev_zero()
    opened_by_sev = _sev_zero()
    closed_by_sev = _sev_zero()
    open_at_start = 0
    week_rows = [
        {"start": (first_week + timedelta(weeks=i)).date().isoformat(), "opened": _sev_zero(), "closed": _sev_zero()}
        for i in range(weeks)
    ]
    mttr: dict[str, list[float]] = {s: [] for s in SEVERITIES}
    hosts: dict[str, dict] = {}
    for host, sev, state, seen, fixed, _ticket in vulns:
        sev = sev if sev in open_by_sev else "info"
        seen, fixed = as_utc(seen), as_utc(fixed)
        if state == "open":
            open_by_sev[sev] += 1
            h = hosts.setdefault(host, {"host": host, "open": 0, "by_severity": _sev_zero()})
            h["open"] += 1
            h["by_severity"][sev] += 1
        if seen and seen < first_week and (fixed is None or fixed >= first_week or state == "open"):
            open_at_start += 1
        if seen and seen >= first_week:
            opened_by_sev[sev] += 1
            week_rows[min(weeks - 1, (seen - first_week).days // 7)]["opened"][sev] += 1
        if state == "fixed" and fixed and fixed >= first_week:
            closed_by_sev[sev] += 1
            week_rows[min(weeks - 1, (fixed - first_week).days // 7)]["closed"][sev] += 1
            if seen:
                mttr[sev].append(max(0.0, (fixed - seen).total_seconds() / 86400))

    tickets = db.execute(
        select(func.coalesce(Ticket.severity_override, Ticket.severity), Ticket.status, Ticket.assignee_id).where(
            Ticket.project_id == project_id
        )
    ).all()
    tickets_by_sev = _sev_zero()
    by_status = {s: 0 for s in STATUSES}
    unassigned = 0
    for sev, status, assignee in tickets:
        by_status[status] = by_status.get(status, 0) + 1
        if status in OPEN_STATUSES:
            tickets_by_sev[sev if sev in tickets_by_sev else "info"] += 1
            if assignee is None:
                unassigned += 1

    host_tickets = dict(
        db.execute(
            select(TicketHost.host, func.count(func.distinct(TicketHost.ticket_id)))
            .join(Ticket, Ticket.id == TicketHost.ticket_id)
            .where(Ticket.project_id == project_id, Ticket.status.in_(OPEN_STATUSES), TicketHost.status != "confirmed")
            .group_by(TicketHost.host)
        ).all()
    )
    rank = {s: i for i, s in enumerate(SEVERITIES)}

    def host_key(h: dict) -> tuple:
        return tuple(-h["by_severity"][s] for s in SEVERITIES) + (h["host"],)

    top = sorted(hosts.values(), key=host_key)[:8]
    for h in top:
        h["tickets"] = host_tickets.get(h["host"], 0)

    recent = db.scalars(
        select(Ticket)
        .where(Ticket.project_id == project_id, Ticket.status == "verified")
        .order_by(Ticket.closed_at.desc().nulls_last(), Ticket.id.desc())
        .limit(6)
    ).all()
    last_run = db.scalars(
        select(ScanRun)
        .where(ScanRun.project_id == project_id)
        .order_by(ScanRun.finished_at.desc().nulls_last(), ScanRun.id.desc())
        .limit(1)
    ).first()
    open_now = sum(open_by_sev.values())
    return {
        "period": period,
        "period_start": first_week.date().isoformat(),
        "generated_at": now,
        "open_tickets": sum(tickets_by_sev.values()),
        "open_vulns": open_now,
        "open_vulns_at_start": open_at_start,
        "delta": open_now - open_at_start,
        "opened": sum(opened_by_sev.values()),
        "closed": sum(closed_by_sev.values()),
        "tickets_by_severity": tickets_by_sev,
        "vulns_by_severity": open_by_sev,
        "opened_by_severity": opened_by_sev,
        "closed_by_severity": closed_by_sev,
        "by_status": by_status,
        "unassigned": unassigned,
        "awaiting_check": by_status.get("fixed", 0),
        "weeks": week_rows,
        "mttr": [
            {"severity": s, "days": round(sum(v) / len(v), 1) if v else None, "count": len(v)}
            for s, v in sorted(mttr.items(), key=lambda kv: rank[kv[0]])
        ],
        "top_hosts": top,
        "recent_verified": [
            {
                "id": t.id,
                "title": t.title,
                "severity": t.effective_severity,
                "closed_at": t.closed_at,
                "hosts": len(t.hosts),
                "evidence": t.evidence,
            }
            for t in recent
        ],
        "last_run": (
            {
                "id": last_run.id,
                "scanner_run_id": last_run.scanner_run_id,
                "name": last_run.name,
                "kind": last_run.kind,
                "finished_at": last_run.finished_at,
            }
            if last_run
            else None
        ),
    }


@router.get("/search")
def search(
    q: str = Query(min_length=1, max_length=200),
    project: str | None = None,
    limit: int = Query(default=6, ge=1, le=20),
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> dict:
    """Быстрый поиск (Ctrl+K и `search_url` манифеста): заявки, хосты, CVE и БДУ.
    Без `project` — по всем доступным проектам."""
    text = q.strip()
    if not text:
        raise HTTPException(422, "Пустой запрос")
    if project:
        get_project(db, project, p)
        projects = [project]
    else:
        stmt = select(Project.id).where(Project.status == "active")
        if "*" not in p.projects:
            stmt = stmt.where(Project.id.in_(p.projects))
        projects = list(db.scalars(stmt))
    like = f"%{text}%"
    num = text.lstrip("№#").strip()

    conds = [Ticket.title.ilike(like)]
    if num.isdigit():
        conds.append(Ticket.id == int(num))
    t_stmt = select(Ticket).where(Ticket.project_id.in_(projects), or_(*conds))
    t_total = db.scalar(select(func.count()).select_from(t_stmt.subquery())) or 0
    exact = Ticket.id == (int(num) if num.isdigit() else -1)
    closed = Ticket.status.in_(CLOSED_STATUSES)
    tickets = db.scalars(t_stmt.order_by(exact.desc(), closed.asc(), Ticket.id).limit(limit)).all()

    host_rows = db.execute(
        select(Vulnerability.host, Vulnerability.project_id, Vulnerability.state, Vulnerability.severity).where(
            Vulnerability.project_id.in_(projects), Vulnerability.host.ilike(like)
        )
    ).all()
    hosts: dict[tuple[str, str], dict] = {}
    for host, pid, state, sev in host_rows:
        h = hosts.setdefault((pid, host), {"host": host, "project_id": pid, "open": 0, "max_severity": None})
        if state == "open":
            h["open"] += 1
            if h["max_severity"] is None or SEVERITIES.index(sev) < SEVERITIES.index(h["max_severity"]):
                h["max_severity"] = sev
    host_list = sorted(hosts.values(), key=lambda h: (-h["open"], h["host"]))

    v_rows = db.execute(
        select(
            Vulnerability.vuln_id,
            Vulnerability.title,
            Vulnerability.severity,
            Vulnerability.cve_ids,
            Vulnerability.bdu_ids,
            Vulnerability.host,
            Vulnerability.state,
            Vulnerability.ticket_id,
            Vulnerability.project_id,
        )
        .where(Vulnerability.project_id.in_(projects), Vulnerability.vuln_id.ilike(like))
        .limit(2000)
    ).all()
    vulns: dict[str, dict] = {}
    for vid, title, sev, cves, bdus, host, state, ticket_id, pid in v_rows:
        v = vulns.setdefault(
            vid,
            {
                "id": vid,
                "title": title,
                "severity": sev,
                "cves": cves or [],
                "bdu_ids": bdus or [],
                "hosts": set(),
                "open": 0,
                "ticket_id": ticket_id,
                "project_id": pid,
            },
        )
        v["hosts"].add(host)
        if state == "open":
            v["open"] += 1
    vuln_list = sorted(vulns.values(), key=lambda v: (-v["open"], SEVERITIES.index(v["severity"]), v["id"]))
    return {
        "q": text,
        "counts": {"tickets": t_total, "hosts": len(host_list), "vulns": len(vuln_list)},
        "tickets": [
            {
                "id": t.id,
                "project_id": t.project_id,
                "title": t.title,
                "severity": t.effective_severity,
                "status": t.status,
                "status_label": STATUSES.get(t.status, t.status),
                "os": t.os,
                "url": f"/tickets/{t.id}?project={t.project_id}",
            }
            for t in tickets
        ],
        "hosts": [{**h, "url": f"/tickets?project={h['project_id']}&host={h['host']}"} for h in host_list[:limit]],
        "vulns": [
            {
                **{k: v[k] for k in ("id", "title", "severity", "cves", "bdu_ids", "open", "ticket_id", "project_id")},
                "host_count": len(v["hosts"]),
                "url": f"/tickets?project={v['project_id']}&q={v['id']}",
            }
            for v in vuln_list[:limit]
        ],
    }
