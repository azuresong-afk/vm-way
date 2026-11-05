"""Исключения (задача 2.5): принятие риска и ложные срабатывания.

Исключение оформляет исполнитель заявки или руководитель: вид, обоснование (для принятия риска —
и компенсирующие меры), утверждающий и дата пересмотра. Утверждает только названный утверждающий
с правом `exception_approve`, и это не тот, кто оформил исключение (четыре глаза). Пока исключение
ждёт утверждения, работа по заявке идёт как обычно; утверждение переводит заявку в «Принят риск»
или «Ложное срабатывание».

Дата пересмотра обязательна для принятия риска (до года вперёд) и необязательна для ложного
срабатывания. **Выбор:** когда дата прошла, исключение истекает само, а заявка возвращается в работу
(в «Нет исправления у производителя», «Назначена» или «Новая»): принятый риск не остаётся принятым
навсегда только потому, что о нём забыли. До даты утверждающий может продлить исключение с причиной.

Ложное срабатывание по желанию отмечается в «Сканере» (`PUT /findings/{id}/false-positive`) —
только если это включено в настройках источника. Снятие или истечение исключения снимает отметку.
Отметку ставит и снимает фоновая задача `exception_sync`, итог — в `sync` исключения.
"""

import logging
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.db import as_utc, utcnow
from app.integrations.scanner import ScannerError
from app.models import (
    Comment,
    Job,
    ScannerSource,
    SourceLink,
    Ticket,
    TicketException,
    TicketHistory,
    User,
    Vulnerability,
)
from app.rbac import Perm, perms_for
from app.services.windows import DEFAULT_TZ, tz_of
from app.services.workflow import CLOSED_STATUSES, Actor, WorkflowError, label, reopen_status

log = logging.getLogger("vm.exceptions")

KINDS = {"risk_accepted": "Принятие риска", "false_positive": "Ложное срабатывание"}
STATUSES = {
    "pending": "Ждёт утверждения",
    "active": "Действует",
    "rejected": "Отклонено",
    "withdrawn": "Отозвано",
    "revoked": "Снято",
    "expired": "Истекло",
}
OPEN = ("pending", "active")
MAX_DAYS = 365  # дата пересмотра — не дальше года вперёд
SOON_DAYS = 14  # «скоро пересмотр»
MIN_REASON = 10


def today() -> date:
    """Сегодня по московскому времени — как у окон обслуживания."""
    return datetime.now(tz_of(DEFAULT_TZ)).date()


def _name(u: User | None) -> str:
    return (u.display_name or u.username) if u else ""


def _date(d: date | None) -> str:
    return d.strftime("%d.%m.%Y") if d else ""


def _user(u: User | None) -> dict | None:
    return {"id": u.id, "username": u.username, "display_name": u.display_name or u.username} if u else None


# --- справочные ---
def open_for(db: Session, ticket_id: int) -> TicketException | None:
    return db.scalar(
        select(TicketException)
        .where(TicketException.ticket_id == ticket_id, TicketException.status.in_(OPEN))
        .order_by(TicketException.id.desc())
    )


def approvers(db: Session) -> list[User]:
    """Активные пользователи с правом утверждать исключения."""
    users = db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.display_name, User.id))
    return [u for u in users if Perm.EXCEPTION_APPROVE in perms_for(u.roles or [], u.extra_perms or [])]


def sync_available(db: Session, project_id: str) -> bool:
    """Можно ли отмечать ложные срабатывания в «Сканере»: хотя бы у одного источника проекта включено."""
    return bool(
        db.scalar(
            select(ScannerSource.id)
            .join(SourceLink, SourceLink.source_id == ScannerSource.id)
            .where(SourceLink.project_id == project_id, ScannerSource.sync_false_positives.is_(True))
            .limit(1)
        )
    )


def can_request(t: Ticket, actor: Actor) -> bool:
    if t.status in CLOSED_STATUSES or not actor.can(Perm.TICKET_WORK):
        return False
    return actor.can(Perm.TICKET_ASSIGN) or t.assignee_id == actor.user.id


def can(ex: TicketException, actor: Actor) -> dict:
    """Что пользователь может сделать с исключением — для кнопок."""
    manage = actor.can(Perm.TICKET_ASSIGN) or actor.can(Perm.EXCEPTION_APPROVE)
    approver = actor.can(Perm.EXCEPTION_APPROVE) and actor.user.id == ex.approver_id
    synced = bool((ex.sync or {}).get("marked"))
    return {
        "approve": ex.status == "pending" and approver and ex.requested_by != actor.user.id,
        "reject": ex.status == "pending" and approver,
        "withdraw": ex.status == "pending" and (ex.requested_by == actor.user.id or actor.can(Perm.TICKET_ASSIGN)),
        "revoke": ex.status == "active" and manage,
        "extend": ex.status == "active" and actor.can(Perm.EXCEPTION_APPROVE),
        "sync": manage
        and ex.kind == "false_positive"
        and ((ex.status == "active" and ex.sync_scanner) or (ex.status not in OPEN and synced)),
    }


# --- общее ---
def _history(db: Session, t: Ticket, actor: Actor | None, action: str, *, from_value="", to_value="", details=None):
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


def _comment(db: Session, t: Ticket, body: str, data: dict | None = None) -> None:
    db.add(Comment(ticket_id=t.id, author_id=None, kind="system", body=body, data=data))


def _audit(db: Session, ex: TicketException, actor: Actor | None, action: str, details: dict | None = None) -> None:
    audit.record(
        db,
        actor.user if actor else None,
        action,
        object_type="exception",
        object_id=ex.id,
        project_id=ex.project_id,
        ip=actor.ip if actor else "",
        details={"exception_id": ex.id, "ticket_id": ex.ticket_id, "kind": ex.kind, **(details or {})},
    )


def _emit(db: Session, ex: TicketException, event: str, extra: dict | None = None) -> None:
    audit.emit(
        db,
        f"vm.exception.{event}",
        ex.project_id,
        f"exception/{ex.id}",
        {
            "exception_id": ex.id,
            "ticket_id": ex.ticket_id,
            "kind": ex.kind,
            "status": ex.status,
            "review_on": ex.review_on.isoformat() if ex.review_on else None,
            **(extra or {}),
        },
    )


def _set_status(db: Session, t: Ticket, actor: Actor | None, to: str, ex: TicketException) -> None:
    """Перевод заявки исключением: история, журнал и событие — как у ручного перевода."""
    old = t.status
    if old == to:
        return
    now = utcnow()
    t.status = to
    t.updated_at = now
    if to in CLOSED_STATUSES:
        t.closed_at = now
    elif old in CLOSED_STATUSES:
        t.closed_at = None
    info = {"from": old, "to": to, "exception_id": ex.id}
    _history(db, t, actor, "status", from_value=old, to_value=to, details={"exception_id": ex.id})
    audit.record(
        db,
        actor.user if actor else None,
        "ticket.status",
        object_type="ticket",
        object_id=t.id,
        project_id=t.project_id,
        ip=actor.ip if actor else "",
        details={"ticket_id": t.id, **info},
    )
    audit.emit(db, "vm.ticket.status_changed", t.project_id, f"ticket/{t.id}", {"ticket_id": t.id, **info})


def _need(text: str | None, what: str, minimum: int = 3) -> str:
    r = (text or "").strip()
    if len(r) < minimum:
        raise WorkflowError(f"{what}: не короче {minimum} символов" if minimum > 3 else f"{what}: укажите причину", 422)
    return r[:4000]


def _check_date(review_on: date | None, required: bool) -> date | None:
    if review_on is None:
        if required:
            raise WorkflowError("Для принятия риска укажите дату пересмотра", 422)
        return None
    now = today()
    if review_on <= now:
        raise WorkflowError("Дата пересмотра должна быть в будущем", 422)
    if review_on > now + timedelta(days=MAX_DAYS):
        raise WorkflowError(f"Дата пересмотра — не дальше чем через {MAX_DAYS} дней", 422)
    return review_on


def _locked_ticket(db: Session, ticket_id: int) -> Ticket:
    return db.scalars(select(Ticket).where(Ticket.id == ticket_id).with_for_update()).one()


# --- действия ---
def request(
    db: Session,
    t: Ticket,
    actor: Actor,
    *,
    kind: str,
    reason: str | None,
    measures: str | None = None,
    approver_id: int | None,
    review_on: date | None,
    sync_scanner: bool = False,
) -> TicketException:
    """Оформить исключение. t — под блокировкой строки."""
    if kind not in KINDS:
        raise WorkflowError(f"Неизвестный вид исключения: {kind}", 422)
    if not actor.can(Perm.TICKET_WORK):
        raise WorkflowError("Недостаточно прав", 403)
    if t.status in CLOSED_STATUSES:
        raise WorkflowError(f"Заявка закрыта («{label(t.status)}»)")
    if not (actor.can(Perm.TICKET_ASSIGN) or t.assignee_id == actor.user.id):
        raise WorkflowError("Исключение оформляет исполнитель заявки или руководитель", 403)
    if open_for(db, t.id):
        raise WorkflowError("У заявки уже есть исключение на утверждении или действующее")
    reason = _need(reason, "Обоснование", MIN_REASON)
    measures = (measures or "").strip()[:4000] if kind == "risk_accepted" else ""
    review_on = _check_date(review_on, required=kind == "risk_accepted")
    if approver_id is None:
        raise WorkflowError("Выберите утверждающего", 422)
    if approver_id == actor.user.id:
        raise WorkflowError("Утверждающий — не тот, кто оформляет исключение", 422)
    approver = db.get(User, approver_id)
    if (
        approver is None
        or not approver.is_active
        or Perm.EXCEPTION_APPROVE not in perms_for(approver.roles or [], approver.extra_perms or [])
    ):
        raise WorkflowError("Утверждающий не найден, отключён или не может утверждать исключения", 422)
    if kind != "false_positive":
        sync_scanner = False
    if sync_scanner and not sync_available(db, t.project_id):
        raise WorkflowError("Отметка в «Сканере» выключена в настройках источника", 422)
    now = utcnow()
    ex = TicketException(
        project_id=t.project_id,
        ticket_id=t.id,
        kind=kind,
        status="pending",
        reason=reason,
        measures=measures,
        review_on=review_on,
        requested_by=actor.user.id,
        requested_at=now,
        approver_id=approver.id,
        prev_status=t.status,
        hosts=[],
        extensions=[],
        sync_scanner=sync_scanner,
        sync={},
        created_at=now,
        updated_at=now,
    )
    db.add(ex)
    db.flush()
    t.updated_at = now
    _history(
        db,
        t,
        actor,
        "exception_requested",
        to_value=KINDS[kind],
        details={"exception_id": ex.id, "approver": _name(approver), "review_on": _date(review_on), "reason": reason},
    )
    _audit(
        db,
        ex,
        actor,
        "exception.request",
        {"approver_id": approver.id, "review_on": _date(review_on), "reason": reason, "sync_scanner": sync_scanner},
    )
    _emit(db, ex, "requested", {"approver_id": approver.id})
    return ex


def _lock(db: Session, ex: TicketException) -> Ticket:
    t = _locked_ticket(db, ex.ticket_id)
    db.refresh(ex)
    return t


def approve(db: Session, ex: TicketException, actor: Actor, note: str | None = None) -> Job | None:
    """Утвердить: заявка переходит в статус исключения. Возвращает задачу отметки в «Сканере», если она нужна."""
    t = _lock(db, ex)
    if ex.status != "pending":
        raise WorkflowError(f"Исключение уже не ждёт утверждения («{STATUSES[ex.status]}»)")
    if not actor.can(Perm.EXCEPTION_APPROVE) or actor.user.id != ex.approver_id:
        raise WorkflowError("Утвердить может только назначенный утверждающий", 403)
    if actor.user.id == ex.requested_by:
        raise WorkflowError("Нельзя утвердить своё исключение", 403)
    if t.status in CLOSED_STATUSES:
        raise WorkflowError(f"Заявка уже закрыта («{label(t.status)}»): отклоните или отзовите исключение")
    now = utcnow()
    ex.status = "active"
    ex.decided_by = actor.user.id
    ex.decided_at = now
    ex.decision_note = (note or "").strip()[:2000]
    ex.prev_status = t.status
    ex.hosts = sorted(h.host for h in t.hosts if h.status != "confirmed")
    ex.vuln_count = len(
        db.scalars(select(Vulnerability.id).where(Vulnerability.ticket_id == t.id, Vulnerability.state == "open")).all()
    )
    ex.updated_at = now
    if t.window_id is not None:
        _history(db, t, actor, "window", from_value=str(t.window_id), details={"exception_id": ex.id})
        t.window_id = None
    _set_status(db, t, actor, ex.kind, ex)
    until = f" до {_date(ex.review_on)}" if ex.review_on else ""
    what = "Принят риск" if ex.kind == "risk_accepted" else "Ложное срабатывание"
    _comment(
        db,
        t,
        f"{what}{until}. Обоснование: {ex.reason}"
        + (f" Компенсирующие меры: {ex.measures}" if ex.measures else "")
        + f" Утвердил: {_name(actor.user)}."
        + (f" Комментарий: {ex.decision_note}" if ex.decision_note else ""),
        {"exception_id": ex.id},
    )
    _audit(db, ex, actor, "exception.approve", {"note": ex.decision_note, "hosts": len(ex.hosts)})
    _emit(db, ex, "approved", {"approved_by": actor.user.id})
    if ex.sync_scanner:
        return _enqueue_sync(db, ex, "mark", actor)
    return None


def reject(db: Session, ex: TicketException, actor: Actor, reason: str | None) -> None:
    t = _lock(db, ex)
    if ex.status != "pending":
        raise WorkflowError(f"Исключение уже не ждёт утверждения («{STATUSES[ex.status]}»)")
    if not actor.can(Perm.EXCEPTION_APPROVE) or actor.user.id != ex.approver_id:
        raise WorkflowError("Отклонить может только назначенный утверждающий", 403)
    reason = _need(reason, "Отклонение")
    now = utcnow()
    ex.status, ex.decided_by, ex.decided_at, ex.decision_note, ex.updated_at = (
        "rejected",
        actor.user.id,
        now,
        reason,
        now,
    )
    t.updated_at = now
    _history(
        db, t, actor, "exception_rejected", to_value=KINDS[ex.kind], details={"exception_id": ex.id, "reason": reason}
    )
    _comment(db, t, f"Исключение «{KINDS[ex.kind]}» отклонено: {reason}", {"exception_id": ex.id})
    _audit(db, ex, actor, "exception.reject", {"reason": reason})
    _emit(db, ex, "rejected")


def withdraw(db: Session, ex: TicketException, actor: Actor, reason: str | None = None) -> None:
    t = _lock(db, ex)
    if ex.status != "pending":
        raise WorkflowError(f"Исключение уже не ждёт утверждения («{STATUSES[ex.status]}»)")
    if ex.requested_by != actor.user.id and not actor.can(Perm.TICKET_ASSIGN):
        raise WorkflowError("Отозвать может тот, кто оформил исключение, или руководитель", 403)
    now = utcnow()
    reason = (reason or "").strip()[:2000]
    ex.status, ex.ended_by, ex.ended_at, ex.end_reason, ex.updated_at = "withdrawn", actor.user.id, now, reason, now
    t.updated_at = now
    _history(
        db, t, actor, "exception_withdrawn", to_value=KINDS[ex.kind], details={"exception_id": ex.id, "reason": reason}
    )
    _audit(db, ex, actor, "exception.withdraw", {"reason": reason})
    _emit(db, ex, "withdrawn")


def _end(db: Session, t: Ticket, ex: TicketException, actor: Actor | None, status: str, reason: str) -> Job | None:
    """Снять действующее исключение: заявка возвращается в работу, отметка в «Сканере» снимается."""
    now = utcnow()
    ex.status, ex.ended_by, ex.ended_at, ex.end_reason, ex.updated_at = (
        status,
        actor.user.id if actor else None,
        now,
        reason,
        now,
    )
    if t.status == ex.kind:
        _set_status(db, t, actor, reopen_status(t), ex)
    return _enqueue_sync(db, ex, "unmark", actor) if (ex.sync or {}).get("marked") else None


def revoke(db: Session, ex: TicketException, actor: Actor, reason: str | None) -> Job | None:
    """Снять исключение досрочно (руководитель или утверждающий, с причиной)."""
    t = _lock(db, ex)
    if ex.status != "active":
        raise WorkflowError(f"Исключение не действует («{STATUSES[ex.status]}»)")
    if not (actor.can(Perm.TICKET_ASSIGN) or actor.can(Perm.EXCEPTION_APPROVE)):
        raise WorkflowError("Снять исключение может руководитель", 403)
    reason = _need(reason, "Снятие исключения")
    job = _end(db, t, ex, actor, "revoked", reason)
    _comment(
        db,
        t,
        f"Исключение «{KINDS[ex.kind]}» снято ({_name(actor.user)}): {reason}. Заявка возвращена в работу.",
        {"exception_id": ex.id},
    )
    _audit(db, ex, actor, "exception.revoke", {"reason": reason})
    _emit(db, ex, "revoked")
    return job


def extend(db: Session, ex: TicketException, actor: Actor, review_on: date | None, reason: str | None) -> None:
    """Продлить: новая дата пересмотра (утверждающий, с причиной)."""
    t = _lock(db, ex)
    if ex.status != "active":
        raise WorkflowError(f"Исключение не действует («{STATUSES[ex.status]}»)")
    if not actor.can(Perm.EXCEPTION_APPROVE):
        raise WorkflowError("Продлить исключение может утверждающий", 403)
    if review_on is None:
        raise WorkflowError("Укажите новую дату пересмотра", 422)
    review_on = _check_date(review_on, required=True)
    if review_on == ex.review_on:
        raise WorkflowError("Дата пересмотра не изменилась")
    reason = _need(reason, "Продление")
    old = ex.review_on
    now = utcnow()
    ex.review_on = review_on
    ex.extensions = [
        *(ex.extensions or []),
        {
            "at": now.isoformat(),
            "by": actor.user.id,
            "by_name": _name(actor.user),
            "from": _date(old),
            "to": _date(review_on),
            "reason": reason,
        },
    ]
    ex.updated_at = now
    t.updated_at = now
    _history(
        db,
        t,
        actor,
        "exception_extended",
        from_value=_date(old),
        to_value=_date(review_on),
        details={"exception_id": ex.id, "reason": reason},
    )
    _comment(
        db,
        t,
        f"Исключение «{KINDS[ex.kind]}» продлено до {_date(review_on)} ({_name(actor.user)}): {reason}",
        {"exception_id": ex.id},
    )
    _audit(db, ex, actor, "exception.extend", {"from": _date(old), "to": _date(review_on), "reason": reason})
    _emit(db, ex, "extended", {"from": old.isoformat() if old else None})


def expire_due(db: Session, on: date | None = None) -> list[Job]:
    """Истекают исключения, у которых прошла дата пересмотра. Коммит — у вызывающего."""
    on = on or today()
    due = db.scalars(
        select(TicketException)
        .where(
            TicketException.status == "active", TicketException.review_on.is_not(None), TicketException.review_on < on
        )
        .order_by(TicketException.id)
    ).all()
    out: list[Job] = []
    for ex in due:
        t = _lock(db, ex)
        if ex.status != "active":
            continue
        reason = f"Наступила дата пересмотра {_date(ex.review_on)}"
        job = _end(db, t, ex, None, "expired", reason)
        _comment(
            db,
            t,
            f"Исключение «{KINDS[ex.kind]}» истекло: {_date(ex.review_on)} — дата пересмотра, продления не было. "
            "Заявка возвращена в работу.",
            {"exception_id": ex.id},
        )
        _audit(db, ex, None, "exception.expire", {"review_on": _date(ex.review_on)})
        _emit(db, ex, "expired")
        if job:
            out.append(job)
    return out


# --- отметка в «Сканере» ---
def _enqueue_sync(db: Session, ex: TicketException, action: str, actor: Actor | None) -> Job | None:
    ex.sync = {**(ex.sync or {}), "action": action, "state": "queued"}
    return jobs.enqueue(
        db,
        "exception_sync",
        {"exception_id": ex.id, "action": action},
        project_id=ex.project_id,
        title=("Отметка" if action == "mark" else "Снятие отметки")
        + f" ложного срабатывания в «Сканере» (№{ex.ticket_id})",
        created_by=actor.user.username if actor else "",
    )


def request_sync(db: Session, ex: TicketException, actor: Actor) -> Job | None:
    """Повторить отметку (или снятие отметки) в «Сканере» по кнопке."""
    flags = can(ex, actor)
    if not flags["sync"]:
        raise WorkflowError(
            "Отметка в «Сканере» для этого исключения недоступна", 403 if ex.kind == "false_positive" else 409
        )
    running = db.scalars(select(Job).where(Job.kind == "exception_sync", Job.status.in_(["queued", "running"])))
    if any((j.payload or {}).get("exception_id") == ex.id for j in running):
        raise WorkflowError("Отметка в «Сканере» уже выполняется")
    action = "mark" if ex.status == "active" else "unmark"
    job = _enqueue_sync(db, ex, action, actor)
    _audit(db, ex, actor, "exception.sync_request", {"action": action})
    return job


def run_sync(db: Session, ex: TicketException, action: str) -> dict:
    """Ставит или снимает отметку по всем уязвимостям заявки. Ошибка по одной находке не останавливает другие."""
    from app.services.importer import client_for

    if action == "mark" and ex.status != "active":
        ex.sync = {**(ex.sync or {}), "state": "skipped", "note": "исключение уже не действует"}
        return {"skipped": True}
    marked = set((ex.sync or {}).get("marked") or [])
    vulns = list(
        db.scalars(select(Vulnerability).where(Vulnerability.ticket_id == ex.ticket_id).order_by(Vulnerability.id))
    )
    if action == "unmark":
        vulns = [v for v in vulns if v.dedup_key in marked]
    done = failed = skipped = 0
    errors: list[dict] = []
    by_source: dict[int | None, list[Vulnerability]] = {}
    for v in vulns:
        by_source.setdefault(v.source_id, []).append(v)
    reason = f"«Устранение», заявка №{ex.ticket_id}: {ex.reason}"[:2000]
    for source_id, items in by_source.items():
        src = db.get(ScannerSource, source_id) if source_id else None
        if src is None or (action == "mark" and not src.sync_false_positives):
            skipped += len(items)
            errors.append(
                {"host": "", "vuln": "", "error": f"{len(items)} — отметка в «Сканере» выключена в источнике"}
            )
            continue
        client = client_for(src)
        for v in items:
            label_ = v.vuln_id or (v.cve_ids[0] if v.cve_ids else v.title)
            if not v.scanner_finding_id:
                skipped += 1
                errors.append({"host": v.host, "vuln": label_, "error": "нет номера находки «Сканера»"})
                continue
            try:
                if action == "mark":
                    client.mark_false_positive(v.scanner_finding_id, reason)
                    marked.add(v.dedup_key)
                else:
                    client.unmark_false_positive(v.scanner_finding_id)
                    marked.discard(v.dedup_key)
                done += 1
            except ScannerError as e:
                failed += 1
                msg = str(e)
                if e.status == 403:
                    msg = "у сервисной учётки нет права отмечать ложные срабатывания (нужна роль operator)"
                elif e.status == 404:
                    msg = "находка не найдена в «Сканере»"
                errors.append({"host": v.host, "vuln": label_, "error": msg})
                if e.status in (401, 403) or e.status is None:
                    # Без прав или без связи остальные находки этого источника не пройдут.
                    rest = items[items.index(v) + 1 :]
                    failed += len(rest)
                    break
    state = "done" if not failed and not skipped else ("failed" if not done else "partial")
    if not vulns:
        state = "done"
    ex.sync = {
        "action": action,
        "state": state,
        "at": utcnow().isoformat(),
        "done": done,
        "failed": failed,
        "skipped": skipped,
        "total": len(vulns),
        "marked": sorted(marked),
        "errors": errors[:50],
    }
    ex.updated_at = utcnow()
    t = db.get(Ticket, ex.ticket_id)
    verb = "Отмечено ложным срабатыванием" if action == "mark" else "Снята отметка ложного срабатывания"
    tail = f"; не удалось — {failed + skipped}: {errors[0]['error']}" if errors else ""
    if t is not None:
        _comment(db, t, f"{verb} в «Сканере»: {done} из {len(vulns)}{tail}.", {"exception_id": ex.id, "sync": state})
    _audit(
        db,
        ex,
        None,
        "exception.sync",
        {"action": action, "state": state, "done": done, "failed": failed, "skipped": skipped},
    )
    return {"state": state, "done": done, "failed": failed, "skipped": skipped}


@jobs.handler("exception_sync")
def _sync_job(db: Session, job: Job) -> dict:
    ex = db.get(TicketException, job.payload["exception_id"])
    if ex is None:
        return {"skipped": True}
    out = run_sync(db, ex, job.payload.get("action", "mark"))
    db.commit()
    return out


# --- вывод ---
def exception_out(ex: TicketException, db: Session | None = None, actor: Actor | None = None) -> dict:
    t = ex.ticket
    now = today()
    days_left = (ex.review_on - now).days if ex.review_on else None
    hosts_now = sorted(h.host for h in t.hosts) if t else []
    out = {
        "id": ex.id,
        "project_id": ex.project_id,
        "ticket": {
            "id": t.id,
            "title": t.title,
            "status": t.status,
            "severity": t.effective_severity,
            "os": t.os,
            "kind": t.kind,
        }
        if t
        else None,
        "kind": ex.kind,
        "kind_label": KINDS.get(ex.kind, ex.kind),
        "status": ex.status,
        "status_label": STATUSES.get(ex.status, ex.status),
        "reason": ex.reason,
        "measures": ex.measures,
        "review_on": ex.review_on,
        "days_left": days_left,
        "review_soon": ex.status == "active" and days_left is not None and days_left <= SOON_DAYS,
        "requested_by": _user(ex.requester),
        "requested_at": ex.requested_at,
        "approver": _user(ex.approver),
        "decided_by": _user(ex.decider),
        "decided_at": ex.decided_at,
        "decision_note": ex.decision_note,
        "ended_by": _user(ex.ender),
        "ended_at": ex.ended_at,
        "end_reason": ex.end_reason,
        "prev_status": ex.prev_status,
        "hosts": ex.hosts or [],
        "hosts_now": len(hosts_now),
        "new_hosts": [h for h in hosts_now if ex.status == "active" and h not in set(ex.hosts or [])],
        "vuln_count": ex.vuln_count,
        "extensions": ex.extensions or [],
        "sync_scanner": ex.sync_scanner,
        "sync": ex.sync or {},
        "created_at": ex.created_at,
        "updated_at": as_utc(ex.updated_at),
    }
    if actor is not None:
        out["can"] = can(ex, actor)
    return out
