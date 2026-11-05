"""Ход работ по заявке (задача 1.5): назначение, переходы статусов, переопределение уровня,
комментарии и наблюдатели.

Каждое изменение пишет строку в историю заявки, запись в журнал аудита и доменное событие
в outbox — всё в одной транзакции с самим изменением. Коммит делает вызывающий код.

Переходы, которые человек делает вручную, перечислены в `MANUAL`. Статусы «Подтверждено»,
«Не подтверждено», «Регрессия» и «Нет исправления у производителя» ставит только система
(импорт и повторная проверка, задачи 1.4 и 1.6), вручную в них перейти нельзя.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import utcnow
from app.models import Comment, Ticket, TicketHistory, TicketWatcher, User
from app.rbac import Perm, perms_for

STATUSES = {
    "new": "Новая",
    "assigned": "Назначена",
    "in_progress": "В работе",
    "waiting_window": "Ожидает окна",
    "fixed": "Исправлено, ждёт проверки",
    "verified": "Подтверждено",
    "not_verified": "Не подтверждено",
    "risk_accepted": "Принят риск",
    "false_positive": "Ложное срабатывание",
    "no_vendor_fix": "Нет исправления у производителя",
    "regression": "Регрессия",
}
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Работа по заявке идёт: снятие исполнителя возвращает такую заявку в «Новая».
WORK_STATUSES = {"assigned", "in_progress", "waiting_window"}
# Исключения (задача 2.5): в эти статусы заявку переводит только утверждённое исключение
# (app/services/exceptions.py), обратно — его снятие или истечение. Вручную через /status — нельзя.
EXCEPTION_STATUSES = {"risk_accepted", "false_positive"}
CLOSED_STATUSES = {"verified"} | EXCEPTION_STATUSES
# Ставит только система (импорт, повторная проверка).
SYSTEM_STATUSES = {"verified", "not_verified", "regression", "no_vendor_fix"}

_WORK = {"in_progress", "waiting_window", "fixed"}
MANUAL: dict[str, set[str]] = {
    "new": set(),  # в «Назначена» — только назначением исполнителя
    "assigned": set(_WORK),
    "in_progress": {"waiting_window", "fixed"},
    "waiting_window": {"in_progress", "fixed"},
    "fixed": {"in_progress"},  # вернуть в работу, не дожидаясь проверки (с причиной)
    "not_verified": set(_WORK),
    "regression": set(_WORK),
    "no_vendor_fix": set(),
    "verified": set(),  # повторное появление уязвимости откроет заявку как «Регрессия» (задача 1.6)
    "risk_accepted": set(),  # возврат — снятие или истечение исключения
    "false_positive": set(),
}
# Переходы, для которых причина обязательна.
REASON_REQUIRED = {"return"}


class WorkflowError(Exception):
    def __init__(self, message: str, code: int = 409):
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class Actor:
    user: User
    perms: set[str]
    ip: str = ""

    def can(self, perm: Perm | str) -> bool:
        return str(perm) in self.perms


def label(status: str) -> str:
    return STATUSES.get(status, status)


def _name(u: User | None) -> str:
    return (u.display_name or u.username) if u else ""


def reopen_status(t: Ticket) -> str:
    """Куда возвращается заявка из исключения."""
    if t.scanner_kind == "package_nofix":
        return "no_vendor_fix"
    return "assigned" if t.assignee_id else "new"


def _kind(t: Ticket, to: str) -> str:
    """Вид перехода: return — из «Исправлено» обратно в работу, work — остальные."""
    return "return" if t.status == "fixed" else "work"


def allowed_targets(t: Ticket, actor: Actor) -> list[str]:
    """Статусы, в которые этот пользователь может перевести заявку прямо сейчас."""
    targets = set(MANUAL.get(t.status, set()))
    out = []
    for to in sorted(targets, key=list(STATUSES).index):
        try:
            _check_transition(t, actor, to)
        except WorkflowError:
            continue
        out.append(to)
    return out


def _check_transition(t: Ticket, actor: Actor, to: str) -> str:
    if to not in STATUSES:
        raise WorkflowError(f"Неизвестный статус: {to}", 422)
    if to == t.status:
        raise WorkflowError(f"Заявка уже в статусе «{label(to)}»")
    if to in EXCEPTION_STATUSES:
        raise WorkflowError(
            f"«{label(to)}» ставится исключением: оформите его с обоснованием, утверждающим и датой пересмотра", 409
        )
    if t.status in EXCEPTION_STATUSES:
        raise WorkflowError("Заявка в исключении: чтобы вернуть её в работу, снимите исключение")
    allowed = MANUAL.get(t.status, set())
    if to not in allowed:
        if to in SYSTEM_STATUSES:
            raise WorkflowError(f"Статус «{label(to)}» ставит только система по итогам импорта или проверки")
        raise WorkflowError(f"Переход «{label(t.status)}» → «{label(to)}» не разрешён")
    kind = _kind(t, to)
    if not actor.can(Perm.TICKET_WORK):
        raise WorkflowError("Недостаточно прав", 403)
    if t.assignee_id is None:
        raise WorkflowError("Сначала назначьте исполнителя")
    if t.assignee_id != actor.user.id and not actor.can(Perm.TICKET_ASSIGN):
        raise WorkflowError("Менять статус может исполнитель заявки или руководитель", 403)
    return kind


def _history(
    db: Session, t: Ticket, actor: Actor | None, action: str, *, from_value="", to_value="", details: dict | None = None
) -> None:
    """actor None — изменение сделала система (импорт, правило назначения)."""
    db.add(
        TicketHistory(
            ticket_id=t.id,
            actor_id=actor.user.id if actor else None,
            action=action,
            from_value=str(from_value)[:200],
            to_value=str(to_value)[:200],
            details=details,
        )
    )


def _audit(db: Session, t: Ticket, actor: Actor | None, action: str, details: dict) -> None:
    audit.record(
        db,
        actor.user if actor else None,
        action,
        object_type="ticket",
        object_id=t.id,
        project_id=t.project_id,
        ip=actor.ip if actor else "",
        details={"ticket_id": t.id, **details},
    )


def _touch(t: Ticket) -> None:
    t.updated_at = utcnow()


def watch(db: Session, t: Ticket, user: User, on: bool = True) -> bool:
    """Подписывает пользователя на заявку (или отписывает). Возвращает True, если что-то изменилось."""
    row = db.get(TicketWatcher, (t.id, user.id))
    if on and row is None:
        db.add(TicketWatcher(ticket_id=t.id, user_id=user.id))
        return True
    if not on and row is not None:
        db.delete(row)
        return True
    return False


def _need_reason(reason: str | None, what: str) -> str:
    r = (reason or "").strip()
    if len(r) < 3:
        raise WorkflowError(f"{what}: укажите причину", 422)
    return r[:2000]


def change_status(db: Session, t: Ticket, actor: Actor, to: str, reason: str | None = None) -> None:
    kind = _check_transition(t, actor, to)
    reason = (reason or "").strip()[:2000]
    if kind in REASON_REQUIRED or to in REASON_REQUIRED:
        reason = _need_reason(reason, f"Переход в «{label(to)}»")
    old = t.status
    t.status = to
    if to in CLOSED_STATUSES:
        t.closed_at = utcnow()
    elif old in CLOSED_STATUSES:
        t.closed_at = None
    _touch(t)
    details = {"from": old, "to": to}
    if reason:
        details["reason"] = reason
    _history(db, t, actor, "status", from_value=old, to_value=to, details={"reason": reason} if reason else None)
    _audit(db, t, actor, "ticket.status", details)
    audit.emit(db, "vm.ticket.status_changed", t.project_id, f"ticket/{t.id}", details)


def _check_assignee(db: Session, assignee_id: int) -> User:
    u = db.get(User, assignee_id)
    if u is None or not u.is_active:
        raise WorkflowError("Пользователь не найден или отключён", 422)
    if Perm.TICKET_WORK not in perms_for(u.roles or [], u.extra_perms or []):
        raise WorkflowError(f"{_name(u)} не может работать с заявками: нужна роль исполнителя или руководителя", 422)
    return u


def assign(
    db: Session,
    t: Ticket,
    actor: Actor | None,
    assignee_id: int | None,
    *,
    via: str = "assign",
    extra: dict | None = None,
) -> bool:
    """Назначает исполнителя (None — снять). Возвращает False, если ничего не изменилось.

    actor None — назначает система по правилу назначения (via="rule", в extra — правило)."""
    if t.status in CLOSED_STATUSES:
        raise WorkflowError(f"Заявка закрыта («{label(t.status)}»): назначение не меняется")
    new = _check_assignee(db, assignee_id) if assignee_id is not None else None
    if t.assignee_id == assignee_id:
        return False
    old = t.assignee
    t.assignee_id = assignee_id
    t.assignee = new
    old_status = t.status
    if new is not None and t.status == "new":
        t.status = "assigned"
    elif new is None and t.status in WORK_STATUSES:
        t.status = "new"
    _touch(t)
    if new is not None:
        watch(db, t, new)
    details = {
        "from": old.id if old else None,
        "to": new.id if new else None,
        "from_name": _name(old),
        "to_name": _name(new),
        "via": via,
        **(extra or {}),
    }
    _history(
        db, t, actor, "assigned" if new else "unassigned", from_value=_name(old), to_value=_name(new), details=details
    )
    if t.status != old_status:
        _history(db, t, actor, "status", from_value=old_status, to_value=t.status, details={"via": via})
        details["status"] = {"from": old_status, "to": t.status}
    _audit(db, t, actor, "ticket.take" if via == "take" else "ticket.assign", details)
    audit.emit(
        db,
        "vm.ticket.assigned",
        t.project_id,
        f"ticket/{t.id}",
        {"ticket_id": t.id, "assignee_id": assignee_id, "status": t.status},
    )
    return True


def take(db: Session, t: Ticket, actor: Actor) -> bool:
    """«Взять»: назначить заявку на себя. Чужую заявку перехватить нельзя — это делает руководитель."""
    if t.assignee_id not in (None, actor.user.id):
        raise WorkflowError(f"Заявка уже назначена: {_name(t.assignee)}")
    return assign(db, t, actor, actor.user.id, via="take")


def override(
    db: Session, t: Ticket, actor: Actor, *, severity: str | None, priority: str | None, reason: str | None
) -> None:
    """Переопределение уровня и приоритета «Сканера». None — вернуть значение «Сканера»."""
    if severity is not None and severity not in SEVERITIES:
        raise WorkflowError(f"Неизвестный уровень: {severity}", 422)
    priority = (priority or "").strip()[:64] or None
    if severity == t.severity:
        severity = None
    if priority == t.priority_label:
        priority = None
    if (severity, priority) == (t.severity_override, t.priority_override):
        raise WorkflowError("Ничего не изменилось")
    reason = _need_reason(reason, "Переопределение уровня")
    before = {"severity": t.effective_severity, "priority": t.priority_override or t.priority_label}
    t.severity_override = severity
    t.priority_override = priority
    t.override_reason = reason if (severity or priority) else ""
    _touch(t)
    after = {"severity": t.effective_severity, "priority": t.priority_override or t.priority_label}
    details = {"before": before, "after": after, "reason": reason, "reset": not (severity or priority)}
    _history(
        db,
        t,
        actor,
        "override",
        from_value=f"{before['severity']} / {before['priority']}",
        to_value=f"{after['severity']} / {after['priority']}",
        details={"reason": reason},
    )
    _audit(db, t, actor, "ticket.override", details)
    audit.emit(db, "vm.ticket.overridden", t.project_id, f"ticket/{t.id}", {"ticket_id": t.id, **details})


def add_comment(db: Session, t: Ticket, actor: Actor, body: str) -> Comment:
    text = (body or "").strip()
    if not text:
        raise WorkflowError("Пустой комментарий", 422)
    c = Comment(ticket_id=t.id, author_id=actor.user.id, kind="user", body=text)
    db.add(c)
    watch(db, t, actor.user)
    _touch(t)
    db.flush()
    _audit(db, t, actor, "ticket.comment", {"comment_id": c.id, "length": len(text)})
    audit.emit(
        db,
        "vm.ticket.commented",
        t.project_id,
        f"ticket/{t.id}",
        {"ticket_id": t.id, "comment_id": c.id, "author": actor.user.username},
    )
    return c


def set_watch(db: Session, t: Ticket, actor: Actor, on: bool) -> bool:
    changed = watch(db, t, actor.user, on)
    if changed:
        _audit(db, t, actor, "ticket.watch" if on else "ticket.unwatch", {})
    return changed


def watchers(db: Session, t: Ticket) -> list[User]:
    return list(
        db.scalars(
            select(User).join(TicketWatcher, TicketWatcher.user_id == User.id).where(TicketWatcher.ticket_id == t.id)
        )
    )
