"""Окна обслуживания и план работ в окне (задача 2.1).

Окно бывает трёх видов:
- `once` — разовое: интервал `starts_at…ends_at`;
- `recurring` — повторяющееся: дни недели, время начала в часовом поясе окна и длительность
  («вторник 22:00–02:00» — день 1, начало 22:00, 240 минут), действует с `valid_from`
  по `valid_until` включительно;
- `blackout` — блэкаут: интервал, в который изменения запрещены.

Охват окна — хосты списка плюс хосты групп активов «Сканера» (группы — с задачи 2.2, по имени,
состав берётся на момент расчёта); ни хостов, ни групп — все хосты проекта. Блэкаут без охвата
запрещает работы во всём проекте, с охватом — только на его хостах.

Выбор: даты повторяющегося окна, которые хоть немного пересекаются с блэкаутом, выпадают
целиком (для своих хостов): обрезанное окно легко принять за полноценное.

План даты окна — заявки, поставленные в окно, по порядку приоритета, с оценкой длительности.
Выбор: до раскаток (задача 2.4) длительность оценивается по виду заявки и числу хостов —
канарейка и партии по 10 %, как будет в раскатке; в итог «закроет N уязвимостей» входят
только заявки, которые помещаются в окно.
"""

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import as_utc, utcnow
from app.models import MaintenanceWindow, Ticket, Vulnerability
from app.rbac import Perm
from app.services.workflow import (
    CLOSED_STATUSES,
    SEVERITIES,
    Actor,
    WorkflowError,
    _audit,
    _history,
    label,
)

KINDS = {"once": "Разовое", "recurring": "Повторяющееся", "blackout": "Блэкаут"}
WORK_KINDS = {"once", "recurring"}
WEEKDAYS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]
DEFAULT_TZ = "Europe/Moscow"
MAX_DURATION_MINUTES = 7 * 24 * 60
MAX_RANGE_DAYS = 400
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,254}$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

# Оценка длительности одного этапа раскатки (канарейка или партия), минуты, по виду заявки.
STAGE_MINUTES = {"package": 10, "kernel": 15, "software": 20, "config": 15, "account": 10, "other": 20}
REBOOT_MINUTES = 10
BATCH_SHARE = 0.10


class WindowError(Exception):
    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.message = message
        self.code = code


def tz_of(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise WindowError(f"Неизвестный часовой пояс: {name}")


def clean_hosts(hosts: list[str] | None) -> list[str]:
    out: list[str] = []
    for h in hosts or []:
        h = h.strip()
        if not h:
            continue
        if not HOST_RE.match(h):
            raise WindowError(f"Недопустимое имя хоста: {h[:80]}")
        if h not in out:
            out.append(h)
    return out


def validate(w: MaintenanceWindow) -> None:
    """Проверка полей окна после создания или изменения."""
    if w.kind not in KINDS:
        raise WindowError(f"Неизвестный вид окна: {w.kind}")
    if not (w.name or "").strip():
        raise WindowError("Укажите название окна")
    tz_of(w.timezone)
    if w.kind == "recurring":
        if not w.weekdays or any(not isinstance(d, int) or d < 0 or d > 6 for d in w.weekdays):
            raise WindowError("Выберите дни недели")
        w.weekdays = sorted(set(w.weekdays))
        if not TIME_RE.match(w.start_time or ""):
            raise WindowError("Время начала — в формате ЧЧ:ММ")
        if not 15 <= (w.duration_minutes or 0) <= MAX_DURATION_MINUTES:
            raise WindowError("Длительность — от 15 минут до 7 суток")
        if w.valid_from and w.valid_until and w.valid_until < w.valid_from:
            raise WindowError("Дата окончания раньше даты начала")
        w.starts_at = w.ends_at = None
    else:
        if w.starts_at is None or w.ends_at is None:
            raise WindowError("Укажите начало и конец")
        if as_utc(w.ends_at) <= as_utc(w.starts_at):
            raise WindowError("Конец должен быть позже начала")
        if as_utc(w.ends_at) - as_utc(w.starts_at) > timedelta(days=MAX_RANGE_DAYS):
            raise WindowError(f"Интервал длиннее {MAX_RANGE_DAYS} дней")
        if w.kind == "once" and as_utc(w.ends_at) - as_utc(w.starts_at) > timedelta(minutes=MAX_DURATION_MINUTES):
            raise WindowError("Разовое окно — не длиннее 7 суток")
        w.weekdays, w.start_time, w.duration_minutes = [], "", 0
        w.valid_from = w.valid_until = None
    w.hosts = clean_hosts(w.hosts)
    groups: list[str] = []
    for g in w.groups or []:
        g = str(g).strip()[:128]
        if g and g not in groups:
            groups.append(g)
    w.groups = groups


def scopes_for(db: Session, windows: list[MaintenanceWindow]) -> dict[int, frozenset[str] | None]:
    """Охват окон: хосты списка и групп; None — весь проект. Пустое множество — никого (группы пусты)."""
    from app.services.assets import group_hosts

    out: dict[int, frozenset[str] | None] = {}
    for w in windows:
        if not w.hosts and not w.groups:
            out[w.id] = None
        else:
            out[w.id] = frozenset(w.hosts or []) | frozenset(group_hosts(db, w.project_id, w.groups or []))
    return out


def schedule_text(w: MaintenanceWindow) -> str:
    """Расписание словами: «вт, чт 22:00–02:00 (Europe/Moscow)»."""
    tz = tz_of(w.timezone)
    if w.kind == "recurring":
        hh, mm = (int(x) for x in w.start_time.split(":"))
        end = datetime.combine(date(2000, 1, 3), time(hh, mm)) + timedelta(minutes=w.duration_minutes)
        days = ", ".join(WEEKDAYS[d] for d in w.weekdays)
        extra = f" +{(end.date() - date(2000, 1, 3)).days} дн." if (end.date() - date(2000, 1, 3)).days > 1 else ""
        return f"{days} {w.start_time}–{end:%H:%M}{extra} ({w.timezone})"
    s = as_utc(w.starts_at).astimezone(tz)
    e = as_utc(w.ends_at).astimezone(tz)
    if s.date() == e.date():
        return f"{s:%d.%m.%Y %H:%M}–{e:%H:%M} ({w.timezone})"
    return f"{s:%d.%m.%Y %H:%M} – {e:%d.%m.%Y %H:%M} ({w.timezone})"


def intervals(w: MaintenanceWindow, start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Интервалы окна (UTC), пересекающиеся с [start, end)."""
    start, end = as_utc(start), as_utc(end)
    if w.kind != "recurring":
        s, e = as_utc(w.starts_at), as_utc(w.ends_at)
        return [(s, e)] if s and e and s < end and e > start else []
    tz = tz_of(w.timezone)
    hh, mm = (int(x) for x in w.start_time.split(":"))
    span = timedelta(minutes=w.duration_minutes)
    out = []
    # Окно, начавшееся раньше `start`, может ещё идти: смотрим назад на длительность окна.
    day = (start - span).astimezone(tz).date() - timedelta(days=1)
    last = end.astimezone(tz).date()
    while day <= last:
        if (
            day.weekday() in w.weekdays
            and (w.valid_from is None or day >= w.valid_from)
            and (w.valid_until is None or day <= w.valid_until)
        ):
            s = datetime.combine(day, time(hh, mm), tzinfo=tz).astimezone(UTC)
            e = s + span
            if s < end and e > start:
                out.append((s, e))
        day += timedelta(days=1)
    return out


@dataclass
class Occurrence:
    window: MaintenanceWindow
    start: datetime
    end: datetime
    blackouts: list[MaintenanceWindow] = field(default_factory=list)
    # Охват окон по id (scopes_for); окна, которых здесь нет, — по списку хостов.
    scopes: dict[int, frozenset[str] | None] = field(default_factory=dict)

    def scope_of(self, w: MaintenanceWindow) -> frozenset[str] | None:
        if w.id in self.scopes:
            return self.scopes[w.id]
        return frozenset(w.hosts) if w.hosts else None

    @property
    def scope(self) -> frozenset[str] | None:
        """Хосты окна; None — весь проект."""
        return self.scope_of(self.window)

    @property
    def blocked_hosts(self) -> set[str] | None:
        """Хосты, закрытые блэкаутом; None — закрыт весь проект."""
        out: set[str] = set()
        for b in self.blackouts:
            sc = self.scope_of(b)
            if sc is None:
                return None
            out |= sc
        return out

    @property
    def cancelled(self) -> bool:
        """Дата выпадает целиком: блэкаут на весь проект или на все хосты окна."""
        blocked = self.blocked_hosts
        if blocked is None:
            return True
        scope = self.scope
        return scope is not None and bool(scope) and scope <= blocked

    def host_allowed(self, host: str) -> bool:
        scope = self.scope
        if scope is not None and host not in scope:
            return False
        blocked = self.blocked_hosts
        return blocked is not None and host not in blocked

    def out(self) -> dict:
        blocked = self.blocked_hosts
        return {
            "window_id": self.window.id,
            "window_name": self.window.name,
            "kind": self.window.kind,
            "start": self.start,
            "end": self.end,
            "cancelled": self.cancelled,
            "blackouts": [{"id": b.id, "name": b.name} for b in self.blackouts],
            "blocked_hosts": None if blocked is None else sorted(blocked),
        }


def project_windows(db: Session, project_id: str, *, active_only: bool = True) -> list[MaintenanceWindow]:
    stmt = select(MaintenanceWindow).where(MaintenanceWindow.project_id == project_id)
    if active_only:
        stmt = stmt.where(MaintenanceWindow.is_active.is_(True))
    return list(db.scalars(stmt.order_by(MaintenanceWindow.id)))


def occurrences(
    windows: list[MaintenanceWindow],
    start: datetime,
    end: datetime,
    *,
    include_blackouts: bool = False,
    scopes: dict[int, frozenset[str] | None] | None = None,
) -> list[Occurrence]:
    """Даты рабочих окон в [start, end) с блэкаутами, которые их задевают, по времени начала.

    scopes — охват окон с группами (scopes_for); без него охват — только список хостов."""
    scopes = scopes or {}
    blackouts = [b for b in windows if b.kind == "blackout" and b.is_active]
    out: list[Occurrence] = []
    for w in windows:
        if w.kind == "blackout":
            if include_blackouts:
                out += [Occurrence(w, s, e, scopes=scopes) for s, e in intervals(w, start, end)]
            continue
        for s, e in intervals(w, start, end):
            # Блэкаут ищем по самой дате окна: она может выходить за [start, end).
            out.append(Occurrence(w, s, e, [b for b in blackouts if intervals(b, s, e)], scopes))
    out.sort(key=lambda o: (o.start, o.window.id))
    return out


def window_occurrences(db: Session, w: MaintenanceWindow, start: datetime, end: datetime) -> list[Occurrence]:
    if w.kind == "blackout":
        return []
    blackouts = [b for b in project_windows(db, w.project_id) if b.kind == "blackout" and b.id != w.id]
    return occurrences([w, *blackouts], start, end, scopes=scopes_for(db, [w, *blackouts]))


def next_occurrence(
    db: Session, w: MaintenanceWindow, at: datetime, *, horizon_days: int = 120, usable: bool = True
) -> Occurrence | None:
    """Текущая или ближайшая дата окна (по умолчанию — не выпавшая из-за блэкаута)."""
    for o in window_occurrences(db, w, at, at + timedelta(days=horizon_days)):
        if not usable or not o.cancelled:
            return o
    return None


def is_open(db: Session, w: MaintenanceWindow, host: str, at: datetime) -> bool:
    """Открыто ли окно для хоста в момент `at` — для запуска раскаток (задача 2.4)."""
    if not w.is_active or w.kind == "blackout":
        return False
    at = as_utc(at)
    return any(o.start <= at < o.end and o.host_allowed(host) for o in window_occurrences(db, w, at, at))


def blackout_at(db: Session, project_id: str, host: str, at: datetime) -> MaintenanceWindow | None:
    """Блэкаут, который сейчас закрывает хост (для раскаток, задача 2.4), или None."""
    blackouts = [b for b in project_windows(db, project_id) if b.kind == "blackout"]
    if not blackouts:
        return None
    at = as_utc(at)
    scopes = scopes_for(db, blackouts)
    for b in blackouts:
        if intervals(b, at, at + timedelta(seconds=1)):
            scope = scopes.get(b.id)
            if scope is None or host in scope:
                return b
    return None


def estimate_minutes(kind: str, hosts: int, reboot: bool) -> int:
    """Оценка длительности раскатки: канарейка (1 хост), затем партии по 10 %."""
    if hosts <= 0:
        return 0
    batch = max(1, math.ceil(hosts * BATCH_SHARE))
    stages = 1 + math.ceil((hosts - 1) / batch)
    return stages * (STAGE_MINUTES.get(kind, STAGE_MINUTES["other"]) + (REBOOT_MINUTES if reboot else 0))


def _sev_rank(t: Ticket) -> int:
    s = t.effective_severity
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)


def window_tickets(db: Session, window_id: int) -> list[Ticket]:
    rows = db.scalars(select(Ticket).where(Ticket.window_id == window_id, Ticket.status.not_in(CLOSED_STATUSES))).all()
    return sorted(rows, key=lambda t: (t.priority_rank if t.priority_rank is not None else 10**6, _sev_rank(t), t.id))


def plan(db: Session, occ: Occurrence) -> dict:
    """План даты окна: заявки по времени, перезагрузки, итог «закроет N уязвимостей»."""
    tickets = window_tickets(db, occ.window.id)
    ids = [t.id for t in tickets]
    open_vulns: dict[int, list[tuple[str, str]]] = {i: [] for i in ids}
    if ids:
        for tid, host, sev in db.execute(
            select(Vulnerability.ticket_id, Vulnerability.host, Vulnerability.severity).where(
                Vulnerability.ticket_id.in_(ids), Vulnerability.state == "open"
            )
        ):
            open_vulns[tid].append((host, sev))
    cursor = occ.start
    items = []
    total = {"vulns": 0, "hosts": set(), "by_severity": {s: 0 for s in SEVERITIES}, "reboots": 0}
    overflow_vulns = 0
    for t in tickets:
        hosts = [h.host for h in t.hosts if h.status != "confirmed"]
        in_scope = [h for h in hosts if occ.host_allowed(h)]
        skipped = []
        for h in hosts:
            if h in in_scope:
                continue
            if occ.scope is not None and h not in occ.scope:
                skipped.append({"host": h, "reason": "не входит в окно"})
            else:
                skipped.append({"host": h, "reason": "блэкаут"})
        vulns = [(h, s) for h, s in open_vulns[t.id] if h in in_scope]
        reboot = bool((t.action or {}).get("reboot"))
        minutes = estimate_minutes(t.kind, len(in_scope), reboot)
        start = cursor if in_scope else None
        end = cursor + timedelta(minutes=minutes) if in_scope else None
        fits = bool(in_scope) and end <= occ.end
        if in_scope:
            cursor = end
        if fits:
            total["vulns"] += len(vulns)
            total["hosts"] |= set(in_scope)
            total["reboots"] += 1 if reboot else 0
            for _, s in vulns:
                total["by_severity"][s if s in SEVERITIES else "info"] += 1
        elif in_scope:
            overflow_vulns += len(vulns)
        items.append(
            {
                "ticket_id": t.id,
                "title": t.title,
                "kind": t.kind,
                "severity": t.effective_severity,
                "status": t.status,
                "assignee": (t.assignee.display_name or t.assignee.username) if t.assignee else None,
                "reboot": reboot,
                "hosts": in_scope,
                "skipped_hosts": skipped,
                "vulns": len(vulns),
                "estimate_minutes": minutes,
                "start": start,
                "end": end,
                "fits": fits,
            }
        )
    return {
        "occurrence": occ.out(),
        "items": items,
        "will_close": total["vulns"],
        "will_close_by_severity": total["by_severity"],
        "hosts": len(total["hosts"]),
        "reboots": total["reboots"],
        "overflow_vulns": overflow_vulns,
        "overflow_tickets": sum(1 for i in items if i["hosts"] and not i["fits"]),
        "planned_minutes": int((cursor - occ.start).total_seconds() // 60),
        "window_minutes": int((occ.end - occ.start).total_seconds() // 60),
    }


def _is_past(w: MaintenanceWindow, now: datetime) -> bool:
    if w.kind == "recurring":
        return w.valid_until is not None and w.valid_until < now.astimezone(tz_of(w.timezone)).date()
    return as_utc(w.ends_at) <= now


def window_out(db: Session, w: MaintenanceWindow, now: datetime, counts: dict[int, int] | None = None) -> dict:
    nxt = next_occurrence(db, w, now) if w.kind != "blackout" and w.is_active else None
    return {
        "id": w.id,
        "project_id": w.project_id,
        "name": w.name,
        "kind": w.kind,
        "kind_label": KINDS.get(w.kind, w.kind),
        "timezone": w.timezone,
        "starts_at": as_utc(w.starts_at),
        "ends_at": as_utc(w.ends_at),
        "weekdays": w.weekdays or [],
        "start_time": w.start_time,
        "duration_minutes": w.duration_minutes,
        "valid_from": w.valid_from,
        "valid_until": w.valid_until,
        "hosts": w.hosts or [],
        "groups": w.groups or [],
        "note": w.note,
        "is_active": w.is_active,
        "schedule": schedule_text(w),
        "next": nxt.out() if nxt else None,
        "past": _is_past(w, now),
        "tickets": (counts or {}).get(w.id, 0),
        "created_at": w.created_at,
        "updated_at": w.updated_at,
    }


# --- Заявка в окне -------------------------------------------------------------------------

# Из этих статусов постановка в окно переводит заявку в «Ожидает окна».
TO_WAITING = {"assigned", "in_progress", "not_verified", "regression"}


def place(db: Session, t: Ticket, actor: Actor, w: MaintenanceWindow | None, *, via: str = "window") -> bool:
    """Ставит заявку в окно (None — снять с окна). Возвращает False, если ничего не изменилось.

    Ставит исполнитель заявки или руководитель. Окно — рабочее (не блэкаут), включённое,
    того же проекта, с предстоящей датой, и хотя бы один неподтверждённый хост заявки входит
    в его охват. Назначенная заявка переходит в «Ожидает окна»; снятие с окна возвращает
    «Ожидает окна» в «В работе»."""
    if t.status in CLOSED_STATUSES:
        raise WorkflowError(f"Заявка закрыта («{label(t.status)}»)")
    if not actor.can(Perm.TICKET_ASSIGN):
        if not actor.can(Perm.TICKET_WORK) or t.assignee_id != actor.user.id:
            raise WorkflowError("Ставить заявку в окно может её исполнитель или руководитель", 403)
    if w is not None:
        if w.project_id != t.project_id:
            raise WorkflowError("Окно из другого проекта", 422)
        if w.kind == "blackout":
            raise WorkflowError("В блэкаут заявку поставить нельзя", 422)
        if not w.is_active:
            raise WorkflowError(f"Окно «{w.name}» отключено")
        nxt = next_occurrence(db, w, utcnow())
        if nxt is None:
            raise WorkflowError(f"У окна «{w.name}» нет предстоящих дат")
        hosts = [h.host for h in t.hosts if h.status != "confirmed"]
        scope = nxt.scope
        if scope is not None and not set(hosts) & scope:
            raise WorkflowError(f"Ни один хост заявки не входит в окно «{w.name}»")
    if t.window_id == (w.id if w else None):
        return False
    old = t.window
    t.window_id = w.id if w else None
    t.window = w
    old_status = t.status
    if w is not None and t.status in TO_WAITING:
        t.status = "waiting_window"
    elif w is None and t.status == "waiting_window":
        t.status = "in_progress"
    t.updated_at = utcnow()
    details = {
        "from": old.id if old else None,
        "to": w.id if w else None,
        "from_name": old.name if old else "",
        "to_name": w.name if w else "",
        "via": via,
    }
    _history(db, t, actor, "window", from_value=details["from_name"], to_value=details["to_name"], details=details)
    if t.status != old_status:
        _history(db, t, actor, "status", from_value=old_status, to_value=t.status, details={"via": via})
        details["status"] = {"from": old_status, "to": t.status}
        audit.emit(
            db,
            "vm.ticket.status_changed",
            t.project_id,
            f"ticket/{t.id}",
            {"ticket_id": t.id, "from": old_status, "to": t.status, "via": via},
        )
    _audit(db, t, actor, "ticket.window", details)
    audit.emit(db, "vm.ticket.scheduled", t.project_id, f"ticket/{t.id}", {"ticket_id": t.id, "window_id": t.window_id})
    return True
