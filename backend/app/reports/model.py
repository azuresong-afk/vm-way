"""Данные отчёта о ходе устранения за период (задача 3.1).

Все форматы (HTML, PDF, DOCX, JSON) строятся из одного словаря, который собирает `build_report`.
JSON-выгрузка — это он и есть, поэтому в нём только простые типы.

Как считается движение уязвимостей. Каждая уязвимость проходит события `appeared` (нашёл прогон),
`fixed` (прогон подтвердил исправление: хост и модуль проверены полностью) и `regression`
(исправленная найдена снова). У события дата прогона, а не импорта. Состояние уязвимости на момент T —
последнее событие до T. Отсюда:

- «На начало» — открытые на начало первого дня периода;
- «Появилось» — события `appeared` внутри периода, «Регрессии» — `regression`, «Закрыто и подтверждено» — `fixed`;
- «На конец» — открытые на конец последнего дня. Всегда верно: на конец = на начало + появилось + регрессии − закрыто.

Уровень берётся текущий (с переопределением заявки, если оно есть), хост — из уязвимости, группа активов —
по адресу хоста (хост в нескольких группах считается в каждой). Заявки, исполнители и исключения — состояние
на момент формирования отчёта: истории назначений по дням продукт не хранит.

Сроков устранения в отчёте нет: политика сроков (задача 3.4) выключена по умолчанию, а в выгружаемый отчёт
сроки попадут только по отдельной галочке. Поле `context.deadlines` зарезервировано под неё и сейчас всегда false.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db import as_utc, utcnow
from app.models import (
    Asset,
    Project,
    ScannerSource,
    ScanRun,
    Ticket,
    TicketException,
    User,
    Vulnerability,
    VulnerabilityEvent,
)
from app.services.closure import run_url
from app.services.exceptions import KINDS as EXCEPTION_KINDS
from app.services.mirror import KIND_LABELS
from app.services.workflow import CLOSED_STATUSES, SEVERITIES, STATUSES

SEVERITY_LABELS = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Информационный",
}
VARIANTS = {"full": "Полный", "brief": "Краткий"}
MAX_DAYS = 3 * 366
NO_GROUP = "Без группы"
UNASSIGNED = "Не назначено"
# Статусы, в которых по заявке идёт работа (для разбивки по исполнителям).
WORK = {"assigned", "in_progress", "waiting_window", "not_verified", "regression"}


class ReportError(Exception):
    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass(slots=True)
class Period:
    date_from: date
    date_to: date
    tz: ZoneInfo

    @property
    def start(self) -> datetime:
        return datetime.combine(self.date_from, time.min, self.tz).astimezone(UTC)

    @property
    def end(self) -> datetime:
        """Начало дня после последнего — граница не включается."""
        return datetime.combine(self.date_to + timedelta(days=1), time.min, self.tz).astimezone(UTC)

    @property
    def days(self) -> int:
        return (self.date_to - self.date_from).days + 1


def make_period(date_from: date | None, date_to: date | None, tz_name: str) -> Period:
    try:
        tz = ZoneInfo(tz_name)
    except (KeyError, ValueError):
        raise ReportError(f"Неизвестный часовой пояс: {tz_name}")
    today = utcnow().astimezone(tz).date()
    date_to = date_to or today
    date_from = date_from or (date_to - timedelta(days=90))
    if date_to > today:
        raise ReportError("Конец периода не может быть в будущем")
    if date_from > date_to:
        raise ReportError("Начало периода позже конца")
    if (date_to - date_from).days + 1 > MAX_DAYS:
        raise ReportError("Период отчёта — не больше трёх лет")
    return Period(date_from, date_to, tz)


def _sev(value: str | None) -> str:
    return value if value in SEVERITY_LABELS else "info"


def _zero() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}


def _counter() -> dict:
    return {"start": 0, "appeared": 0, "regression": 0, "fixed": 0, "end": 0}


def _name(u: User | None) -> str:
    return (u.display_name or u.username) if u else ""


def _iso(d: datetime | date | None) -> str | None:
    if d is None:
        return None
    if isinstance(d, datetime):
        return as_utc(d).isoformat()
    return d.isoformat()


def _local(d: datetime | None, tz: ZoneInfo) -> str:
    return as_utc(d).astimezone(tz).strftime("%d.%m.%Y") if d else ""


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def build_report(
    db: Session,
    project: Project,
    period: Period,
    *,
    variant: str = "full",
    author: User | None = None,
) -> dict:
    if variant not in VARIANTS:
        raise ReportError("Вариант отчёта — full или brief")
    now = utcnow()
    start, end, tz = period.start, period.end, period.tz

    # --- уязвимости и их события ---
    vulns = {v.id: v for v in db.scalars(select(Vulnerability).where(Vulnerability.project_id == project.id))}
    tickets = {
        t.id: t
        for t in db.scalars(
            select(Ticket)
            .where(Ticket.project_id == project.id)
            .options(selectinload(Ticket.hosts), selectinload(Ticket.assignee))
        )
    }
    events = db.execute(
        select(
            VulnerabilityEvent.vulnerability_id,
            VulnerabilityEvent.event,
            VulnerabilityEvent.at,
            VulnerabilityEvent.run_id,
        )
        .join(Vulnerability, Vulnerability.id == VulnerabilityEvent.vulnerability_id)
        .where(
            Vulnerability.project_id == project.id,
            VulnerabilityEvent.event.in_(("appeared", "fixed", "regression")),
        )
        .order_by(VulnerabilityEvent.at, VulnerabilityEvent.id)
    ).all()

    def severity_of(v: Vulnerability) -> str:
        t = tickets.get(v.ticket_id) if v.ticket_id else None
        return _sev(t.effective_severity if t else v.severity)

    # Группы активов по адресу хоста.
    host_groups: dict[str, list[str]] = {}
    for a in db.scalars(select(Asset).where(Asset.project_id == project.id).options(selectinload(Asset.groups))):
        host_groups[a.address] = [g.name for g in a.groups]
        if a.hostname:
            host_groups.setdefault(a.hostname, host_groups[a.address])

    state_start: dict[int, bool] = {}
    state_end: dict[int, bool] = {}
    in_period: dict[int, list[tuple[str, datetime, int | None]]] = defaultdict(list)
    for vid, ev, at, run_id in events:
        at = as_utc(at)
        is_open = ev != "fixed"
        if at < start:
            state_start[vid] = is_open
        if at < end:
            state_end[vid] = is_open
            if at >= start:
                in_period[vid].append((ev, at, run_id))

    by_severity = {s: _counter() for s in SEVERITIES}
    by_group: dict[str, dict] = {}
    by_ticket: dict[int | None, dict] = defaultdict(_counter)
    hosts_end: dict[str, dict[str, int]] = {}
    weeks: dict[date, dict] = {}
    w = _week_start(period.date_from)
    while w <= period.date_to:
        weeks[w] = {"start": w.isoformat(), "opened": _zero(), "closed": _zero()}
        w += timedelta(weeks=1)
    run_moves: dict[int, dict[str, int]] = defaultdict(lambda: {"appeared": 0, "regression": 0, "fixed": 0})

    def bump(c: dict, key: str) -> None:
        c[key] += 1

    for vid, v in vulns.items():
        sev = severity_of(v)
        groups = host_groups.get(v.host) or [NO_GROUP]
        counters = [by_severity[sev], by_ticket[v.ticket_id]] + [
            by_group.setdefault(g, {"name": g, "hosts": set(), **_counter()}) for g in groups
        ]
        for g in groups:
            by_group[g]["hosts"].add(v.host)
        if state_start.get(vid):
            for c in counters:
                bump(c, "start")
        if state_end.get(vid):
            for c in counters:
                bump(c, "end")
            hosts_end.setdefault(v.host, _zero())[sev] += 1
        for ev, at, run_id in in_period.get(vid, []):
            key = {"appeared": "appeared", "regression": "regression", "fixed": "fixed"}[ev]
            for c in counters:
                bump(c, key)
            wk = weeks.get(_week_start(at.astimezone(tz).date()))
            if wk is not None:
                wk["opened" if ev != "fixed" else "closed"][sev] += 1
            if run_id is not None:
                run_moves[run_id][key] += 1

    totals = _counter()
    for c in by_severity.values():
        for k in totals:
            totals[k] += c[k]

    # --- прогоны за период (доказательства) ---
    runs = db.scalars(
        select(ScanRun)
        .where(ScanRun.project_id == project.id, ScanRun.finished_at >= start, ScanRun.finished_at < end)
        .order_by(ScanRun.finished_at, ScanRun.id)
    ).all()
    sources = {
        s.id: s for s in db.scalars(select(ScannerSource).where(ScannerSource.id.in_({r.source_id for r in runs})))
    }
    runs_out = [
        {
            "id": r.id,
            "scanner_run_id": r.scanner_run_id,
            "name": r.name,
            "kind": r.kind,
            "kind_label": "Повторная проверка" if r.kind == "verification" else "Плановый",
            "status": r.status,
            "finished_at": _iso(r.finished_at),
            "finished_local": _local(r.finished_at, tz),
            "url": run_url(sources.get(r.source_id), r.scanner_run_id),
            **run_moves.get(r.id, {"appeared": 0, "regression": 0, "fixed": 0}),
        }
        for r in runs
    ]

    # --- заявки ---
    def ticket_row(t: Ticket) -> dict:
        c = by_ticket.get(t.id) or _counter()
        hosts = t.hosts
        return {
            "id": t.id,
            "title": t.title,
            "kind": t.kind,
            "kind_label": KIND_LABELS.get(t.kind, t.kind),
            "os": t.os,
            "severity": _sev(t.effective_severity),
            "severity_label": SEVERITY_LABELS[_sev(t.effective_severity)],
            "status": t.status,
            "status_label": STATUSES.get(t.status, t.status),
            "assignee": _name(t.assignee) or None,
            "is_regression": t.is_regression,
            "hosts": len(hosts),
            "hosts_confirmed": sum(1 for h in hosts if h.status == "confirmed"),
            "hosts_unverified": sum(1 for h in hosts if h.status == "unverified"),
            "open_vulns": c["end"],
            "fixed_vulns": c["fixed"],
            "closed_at": _iso(t.closed_at),
            "closed_local": _local(t.closed_at, tz),
        }

    rank = {s: i for i, s in enumerate(SEVERITIES)}

    def ticket_key(t: Ticket) -> tuple:
        return (rank[_sev(t.effective_severity)], t.priority_rank or 10**6, t.id)

    def confirmed_at(t: Ticket) -> datetime | None:
        """Дата подтверждения — дата прогона-доказательства, а не момента импорта."""
        raw = (t.evidence or {}).get("finished_at")
        if raw:
            try:
                return as_utc(datetime.fromisoformat(raw))
            except ValueError:
                pass
        return as_utc(t.closed_at)

    verified = []
    for t in sorted(tickets.values(), key=ticket_key):
        closed = confirmed_at(t)
        if t.status == "verified" and closed and start <= closed < end:
            row = ticket_row(t)
            row["closed_at"] = _iso(closed)
            row["closed_local"] = _local(closed, tz)
            ev = t.evidence or {}
            row["evidence"] = {
                "scanner_run_id": ev.get("scanner_run_id"),
                "run_name": ev.get("run_name", ""),
                "kind": ev.get("kind", ""),
                "finished_at": ev.get("finished_at"),
                "url": ev.get("url", ""),
            }
            verified.append(row)
    remaining = [ticket_row(t) for t in sorted(tickets.values(), key=ticket_key) if t.status not in CLOSED_STATUSES]
    unverified_hosts = sum(r["hosts_unverified"] for r in remaining)

    # --- исполнители ---
    people: dict[str, dict] = {}

    def person(name: str) -> dict:
        return people.setdefault(
            name,
            {
                "name": name,
                "open": 0,
                "in_work": 0,
                "awaiting_check": 0,
                "verified": 0,
                "open_vulns": 0,
                "fixed_vulns": 0,
                "by_severity": _zero(),
            },
        )

    verified_ids = {r["id"] for r in verified}
    for t in tickets.values():
        name = _name(t.assignee) or UNASSIGNED
        c = by_ticket.get(t.id) or _counter()
        open_ = t.status not in CLOSED_STATUSES
        if not open_ and t.id not in verified_ids and not c["fixed"]:
            continue
        p = person(name)
        p["fixed_vulns"] += c["fixed"]
        if t.id in verified_ids:
            p["verified"] += 1
        if open_:
            p["open"] += 1
            p["open_vulns"] += c["end"]
            p["by_severity"][_sev(t.effective_severity)] += 1
            if t.status in WORK:
                p["in_work"] += 1
            elif t.status == "fixed":
                p["awaiting_check"] += 1
    assignees = sorted(people.values(), key=lambda p: (p["name"] == UNASSIGNED, -p["open"], -p["verified"], p["name"]))

    # --- группы активов ---
    groups = sorted(
        ({**g, "hosts": len(g["hosts"])} for g in by_group.values()),
        key=lambda g: (g["name"] == NO_GROUP, -g["end"], g["name"]),
    )

    # --- исключения ---
    exc_rows = []
    for ex in db.scalars(
        select(TicketException)
        .where(TicketException.project_id == project.id, TicketException.status == "active")
        .options(selectinload(TicketException.ticket), selectinload(TicketException.approver))
        .order_by(TicketException.review_on.nulls_last(), TicketException.id)
    ):
        exc_rows.append(
            {
                "id": ex.id,
                "ticket_id": ex.ticket_id,
                "ticket_title": ex.ticket.title if ex.ticket else "",
                "severity": _sev(ex.ticket.effective_severity if ex.ticket else "info"),
                "kind": ex.kind,
                "kind_label": EXCEPTION_KINDS.get(ex.kind, ex.kind),
                "reason": ex.reason,
                "measures": ex.measures,
                "approver": _name(ex.approver),
                "approved_at": _iso(ex.decided_at),
                "approved_local": _local(ex.decided_at, tz),
                "review_on": _iso(ex.review_on),
                "review_local": ex.review_on.strftime("%d.%m.%Y") if ex.review_on else "",
                "hosts": len(ex.hosts or []),
                "vulns": ex.vuln_count,
            }
        )

    top_hosts = sorted(
        ({"host": h, "open": sum(c.values()), "by_severity": c} for h, c in hosts_end.items()),
        key=lambda h: tuple(-h["by_severity"][s] for s in SEVERITIES) + (h["host"],),
    )[:10]

    brief = variant == "brief"
    status_counts: dict[str, int] = defaultdict(int)
    for t in tickets.values():
        status_counts[t.status] += 1

    return {
        "context": {
            "title": "Отчёт о ходе устранения уязвимостей",
            "product": "Устранение",
            "project": {
                "id": project.id,
                "name": project.name,
                "client": project.client,
                "contract_ref": project.contract_ref,
            },
            "period": {
                "from": period.date_from.isoformat(),
                "to": period.date_to.isoformat(),
                "days": period.days,
                "timezone": str(tz.key),
                "label": f"{period.date_from:%d.%m.%Y} – {period.date_to:%d.%m.%Y}",
            },
            "variant": variant,
            "variant_label": VARIANTS[variant],
            "generated_at": now.isoformat(),
            "generated_local": now.astimezone(tz).strftime("%d.%m.%Y %H:%M"),
            "author": _name(author),
            "deadlines": False,
            "tickets_as_of_now": period.date_to < now.astimezone(tz).date(),
        },
        "totals": {
            "vulns": totals,
            "tickets_total": len(tickets),
            "tickets_open": len(remaining),
            "tickets_verified": len(verified),
            "tickets_exceptions": len(exc_rows),
            "hosts_unverified": unverified_hosts,
            "by_status": [
                {"status": s, "label": STATUSES[s], "count": status_counts[s]} for s in STATUSES if status_counts[s]
            ],
        },
        "by_severity": [{"severity": s, "label": SEVERITY_LABELS[s], **by_severity[s]} for s in SEVERITIES],
        "weeks": list(weeks.values()),
        "runs": runs_out,
        "assignees": assignees,
        "groups": groups,
        "top_hosts": top_hosts,
        "verified": [] if brief else verified,
        "remaining": [] if brief else remaining,
        "exceptions": exc_rows,
        "key_points": _key_points(totals, len(verified), len(remaining), unverified_hosts, len(exc_rows), by_severity),
    }


def _plural(n: int, one: str, few: str, many: str) -> str:
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return one
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return few
    return many


def _key_points(totals, verified, remaining, unverified, exceptions, by_severity) -> list[str]:
    v = lambda n: f"{n} {_plural(n, 'уязвимость', 'уязвимости', 'уязвимостей')}"  # noqa: E731
    out = [
        f"За период прогоны «Сканера» подтвердили исправление: {v(totals['fixed'])}, "
        f"появилось новых: {totals['appeared']}"
        + (f", вернулось (регрессии) {totals['regression']}" if totals["regression"] else "")
        + ".",
    ]
    delta = totals["end"] - totals["start"]
    if delta < 0:
        out.append(f"Открытых уязвимостей стало меньше на {-delta}: {totals['start']} → {totals['end']}.")
    elif delta > 0:
        out.append(f"Открытых уязвимостей стало больше на {delta}: {totals['start']} → {totals['end']}.")
    else:
        out.append(f"Число открытых уязвимостей не изменилось: {totals['end']}.")
    crit = by_severity["critical"]["end"] + by_severity["high"]["end"]
    if crit:
        out.append(f"Осталось критических и высоких: {v(crit)} — их стоит закрыть в первую очередь.")
    else:
        out.append("Критических и высоких открытых уязвимостей на конец периода нет.")
    out.append(f"Заявок подтверждено за период: {verified}, осталось открытых: {remaining}.")
    if unverified:
        out.append(
            f"На {unverified} {_plural(unverified, 'хосте', 'хостах', 'хостах')} результат не проверен "
            "(хост недоступен или проверка неполная) — отсутствие находки там не считается исправлением."
        )
    if exceptions:
        out.append(f"Действующих исключений (принятый риск, ложное срабатывание): {exceptions}.")
    return out
