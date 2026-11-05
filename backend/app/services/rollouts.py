"""Раскатка исправлений на хосты заявки (задача 2.4).

Ход раскатки:

1. **Подготовка** (`create`) — исполнитель с `remediate_execute`: шаблон, хосты заявки, окно,
   канарейка, доля партии, порог ошибок. Параметры проверяются регулярными выражениями
   (app/services/rollout_templates.py) и дальше не меняются.
2. **Пробный прогон** (`request_dry_run`, задача `rollout_dry_run`) — только чтение и «сухие» режимы
   менеджеров пакетов; показывает, что изменится на каждом хосте. Без него утвердить нельзя.
3. **Утверждение** (`approve`) — руководитель, и это не тот, кто готовил или делал пробный прогон.
   Здесь же — «Разрешить перезагрузку», запуск вне окна (с причиной) и отдельное подтверждение
   произвольной команды.
4. **Запуск** (`start`, задача `rollout`) — исполнитель с `remediate_execute`, не утверждавший.
   Перед каждым этапом заново читается allowlist проекта «Сканера» и проверяется окно: хост вне
   allowlist или вне окна пропускается с записью в журнал аудита. Сначала хост-«канарейка», затем
   партии; канарейка с ошибкой или превышение порога ошибок останавливают раскатку.
5. **Повторная проверка** — по хостам, где изменение прошло, автоматически ставится прицельный
   прогон «Сканера» (app/services/verification.py).

На хосте сохраняются версии «до» и «после», каждая команда с кодом возврата, stdout/stderr и
длительностью. Аварийный стоп не прерывает команду, которая уже идёт на хосте (обрыв менеджера
пакетов посреди установки ломает систему), но новых хостов и перезагрузок после него нет.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import shlex
import time
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.config import get_settings
from app.db import as_utc, utcnow
from app.integrations.scanner import ScannerError
from app.models import (
    Asset,
    Comment,
    Job,
    MaintenanceWindow,
    Project,
    Rollout,
    RolloutHost,
    RolloutStep,
    ScanRun,
    SourceLink,
    Ticket,
    TicketHistory,
    User,
    Vulnerability,
)
from app.rbac import Perm, perms_for
from app.services import credentials, importer, sshexec, verification, windows, workflow
from app.services import rollout_templates as tpl
from app.services.workflow import CLOSED_STATUSES, Actor, WorkflowError

STATUSES = {
    "draft": "Черновик",
    "dry_run": "Пробный прогон",
    "pending_approval": "Ждёт утверждения",
    "approved": "Утверждена",
    "running": "Идёт",
    "done": "Завершена",
    "failed": "Остановлена по ошибкам",
    "stopped": "Аварийный стоп",
    "rejected": "Отклонена",
    "cancelled": "Отменена",
}
HOST_STATUSES = {
    "pending": "Ждёт пробного прогона",
    "dry_ok": "Пробный прогон пройден",
    "dry_failed": "Пробный прогон не прошёл",
    "queued": "В очереди",
    "running": "Выполняется",
    "succeeded": "Изменение выполнено",
    "reboot_pending": "Ждёт перезагрузки",
    "failed": "Ошибка",
    "skipped": "Пропущен",
}
OPEN = {"draft", "dry_run", "pending_approval", "approved", "running"}
FINAL = {"done", "failed", "stopped", "rejected", "cancelled"}
DRY_RUN_TTL = timedelta(days=7)
MAX_HOSTS = 500


class RolloutError(Exception):
    def __init__(self, message: str, code: int = 409):
        super().__init__(message)
        self.message = message
        self.code = code


def label(status: str) -> str:
    return STATUSES.get(status, status)


def _name(u: User | None) -> str:
    return (u.display_name or u.username) if u else "Система"


def _actor_of(user: User) -> Actor:
    return Actor(user=user, perms=perms_for(user.roles or [], user.extra_perms or []))


# ---------- журнал заявки и аудит ----------


def _history(db: Session, r: Rollout, user: User | None, action: str, to: str = "", **details) -> None:
    db.add(
        TicketHistory(
            ticket_id=r.ticket_id,
            actor_id=user.id if user else None,
            action=action,
            to_value=to[:200],
            details={"rollout_id": r.id, **details},
        )
    )


def _audit(
    db: Session, r: Rollout, user: User | None, action: str, ip: str = "", result: str = "ok", **details
) -> None:
    audit.record(
        db,
        user,
        action,
        object_type="rollout",
        object_id=r.id,
        project_id=r.project_id,
        result=result,
        ip=ip,
        details={"rollout_id": r.id, "ticket_id": r.ticket_id, **details},
    )


def _denied(r: Rollout, actor: Actor, action: str, message: str, code: int = 403, **details) -> RolloutError:
    """Отказ пишется в журнал отдельной транзакцией: основная откатывается вместе с ошибкой."""
    audit.record_separately(
        actor.user,
        action,
        object_type="rollout",
        object_id=r.id,
        project_id=r.project_id,
        result="denied",
        ip=actor.ip,
        details={"rollout_id": r.id, "ticket_id": r.ticket_id, "reason": message, **details},
    )
    return RolloutError(message, code)


def _event(db: Session, r: Rollout, **extra) -> None:
    audit.emit(
        db,
        "vm.rollout.status_changed",
        r.project_id,
        f"rollout/{r.id}",
        {"rollout_id": r.id, "ticket_id": r.ticket_id, "status": r.status, **extra},
    )


def _set_status(db: Session, r: Rollout, status: str, **extra) -> None:
    r.status = status
    r.updated_at = utcnow()
    _event(db, r, **extra)


# ---------- подготовка ----------


def _criticality_rank(a: Asset | None) -> int:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(a.criticality, 1) if a else 1


def _ip_key(host: str) -> tuple:
    try:
        ip = ipaddress.ip_address(host)
        return (0, ip.version, int(ip))
    except ValueError:
        return (1, 0, host)


def suggest_canary(db: Session, project_id: str, hosts: list[str]) -> str:
    """Канарейка по умолчанию — наименее критичный хост (при равенстве — меньший адрес)."""
    if not hosts:
        return ""
    assets = {
        a.address: a for a in db.scalars(select(Asset).where(Asset.project_id == project_id, Asset.address.in_(hosts)))
    }
    return min(hosts, key=lambda h: (_criticality_rank(assets.get(h)), _ip_key(h)))


def open_hosts(t: Ticket) -> list[str]:
    return sorted((h.host for h in t.hosts if h.status != "confirmed"), key=_ip_key)


def defaults(db: Session, t: Ticket) -> dict:
    """Предложение для формы «Подготовить раскатку» по заявке."""
    a = t.action or {}
    manager = tpl.default_manager(t.os_family, a.get("manager"))
    template = {"package": "package", "kernel": "kernel"}.get(t.kind, "service")
    if t.status == "no_vendor_fix":
        template = "service"
    packages = list(a.get("packages") or [])
    if template == "kernel" and not packages:
        packages = list(tpl.KERNEL_PACKAGES.get(manager, []))
    hosts = open_hosts(t)
    return {
        "template": template,
        "manager": manager,
        "packages": packages,
        "fixed_version": a.get("fixed_version") or "",
        "service": "",
        "hosts": hosts,
        "canary_host": suggest_canary(db, t.project_id, hosts),
        "window_id": t.window_id,
        "batch_percent": 10,
        "failure_threshold": 10,
        "reboot": bool(a.get("reboot")) or template == "kernel",
    }


def active_for_ticket(db: Session, ticket_id: int) -> Rollout | None:
    return db.scalar(
        select(Rollout).where(Rollout.ticket_id == ticket_id, Rollout.status.in_(OPEN)).order_by(Rollout.id)
    )


def _check_window(db: Session, project_id: str, window_id: int | None) -> MaintenanceWindow | None:
    if window_id is None:
        return None
    w = db.get(MaintenanceWindow, window_id)
    if w is None or w.project_id != project_id:
        raise RolloutError("Окно не найдено в проекте", 422)
    if w.kind == "blackout":
        raise RolloutError("Блэкаут не может быть окном раскатки", 422)
    if not w.is_active:
        raise RolloutError(f"Окно «{w.name}» отключено", 422)
    return w


def create(db: Session, t: Ticket, actor: Actor, data: dict) -> Rollout:
    """Подготовка раскатки по заявке. Коммит — у вызывающего кода."""
    if t.status in CLOSED_STATUSES:
        raise RolloutError(f"Заявка закрыта («{workflow.label(t.status)}»)")
    if not actor.can(Perm.REMEDIATE_EXECUTE):
        raise RolloutError("Готовить раскатку может исполнитель с правом «Запуск раскатки на хостах»", 403)
    other = active_for_ticket(db, t.id)
    if other is not None:
        raise RolloutError(f"По заявке уже есть незавершённая раскатка №{other.id} — завершите или отмените её")
    template = data.get("template") or ""
    if template == "custom" and not actor.can(Perm.CUSTOM_COMMANDS):
        raise RolloutError("Произвольная команда — только с правом «Произвольные команды вне шаблонов»", 403)
    command = data.get("command") or []
    if template == "custom" and isinstance(command, str):
        command = tpl.parse_command(command)
    plan = tpl.build_plan(
        template,
        data.get("manager") or "",
        list(data.get("packages") or []),
        data.get("fixed_version") or "",
        data.get("service") or "",
        list(command),
    )
    allowed = open_hosts(t)
    hosts = list(dict.fromkeys(data.get("hosts") or allowed))
    unknown = [h for h in hosts if h not in allowed]
    if unknown:
        raise RolloutError(f"Хостов нет среди неподтверждённых хостов заявки: {', '.join(unknown[:5])}", 422)
    if not hosts:
        raise RolloutError("Выберите хотя бы один хост", 422)
    if len(hosts) > MAX_HOSTS:
        raise RolloutError(f"Не больше {MAX_HOSTS} хостов в одной раскатке", 422)
    canary = data.get("canary_host") or suggest_canary(db, t.project_id, hosts)
    if canary not in hosts:
        raise RolloutError("Канарейка должна быть среди хостов раскатки", 422)
    batch = int(data.get("batch_percent") or 10)
    threshold = int(data.get("failure_threshold") if data.get("failure_threshold") is not None else 10)
    if not 1 <= batch <= 100:
        raise RolloutError("Доля партии — от 1 до 100 %", 422)
    if not 0 <= threshold <= 100:
        raise RolloutError("Порог ошибок — от 0 до 100 %", 422)
    w = _check_window(db, t.project_id, data.get("window_id"))
    title = {
        "package": f"Обновить {', '.join(plan.packages)}",
        "kernel": f"Обновить ядро ({', '.join(plan.packages)})",
        "service": f"Перезапустить {plan.service}",
        "custom": f"Команда {shlex.join(plan.command)[:120]}",
    }[template]
    r = Rollout(
        project_id=t.project_id,
        ticket_id=t.id,
        title=f"{title} — заявка №{t.id}"[:500],
        template=template,
        manager=plan.manager,
        packages=list(plan.packages),
        fixed_version=plan.fixed_version,
        service=plan.service,
        command=list(plan.command),
        window_id=w.id if w else None,
        canary_host=canary,
        batch_percent=batch,
        failure_threshold=threshold,
        note=str(data.get("note") or "").strip()[:2000],
        prepared_by=actor.user.id,
        status="draft",
    )
    db.add(r)
    db.flush()
    for h in hosts:
        db.add(RolloutHost(rollout_id=r.id, host=h))
    details = {
        "template": template,
        "manager": r.manager,
        "packages": r.packages,
        "fixed_version": r.fixed_version,
        "service": r.service,
        "command": r.command,
        "hosts": hosts,
        "canary_host": canary,
        "window_id": r.window_id,
        "batch_percent": batch,
        "failure_threshold": threshold,
    }
    _history(db, r, actor.user, "rollout_created", r.title)
    _audit(db, r, actor.user, "rollout.create", actor.ip, **details)
    _event(db, r)
    workflow.watch(db, t, actor.user)
    return r


# ---------- проверки перед изменением ----------


def _engagements(db: Session, r: Rollout, hosts: list[str]) -> dict[str, set[tuple[int, int]]]:
    """Проекты «Сканера» каждого хоста: где видели уязвимости заявки, иначе — откуда актив."""
    out: dict[str, set[tuple[int, int]]] = {h: set() for h in hosts}
    rows = db.execute(
        select(Vulnerability.host, ScanRun.source_id, ScanRun.engagement_id)
        .join(ScanRun, ScanRun.id == Vulnerability.last_seen_run_id)
        .where(Vulnerability.ticket_id == r.ticket_id, Vulnerability.host.in_(hosts))
    )
    for host, sid, eid in rows:
        out[host].add((sid, eid))
    for a in db.scalars(select(Asset).where(Asset.project_id == r.project_id, Asset.address.in_(hosts))):
        if not out[a.address] and a.source_id:
            out[a.address].add((a.source_id, a.engagement_id))
    return out


def check_allowlist(db: Session, r: Rollout, hosts: list[str]) -> dict[str, str]:
    """Хосты вне allowlist «Сканера» → причина. allowlist читается заново при каждом вызове.

    «Сканер» не ответил — RolloutError: без свежего allowlist к хостам не подключаемся."""
    denied: dict[str, str] = {}
    nets: dict[tuple[int, int], list] = {}
    for host, engs in _engagements(db, r, hosts).items():
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            denied[host] = "не IP-адрес — allowlist «Сканера» разрешает только адреса"
            continue
        if not engs:
            denied[host] = "не найден проект «Сканера», в котором есть хост"
            continue
        ok = False
        for key in engs:
            if key not in nets:
                link = db.scalar(
                    select(SourceLink).where(
                        SourceLink.project_id == r.project_id,
                        SourceLink.source_id == key[0],
                        SourceLink.engagement_id == key[1],
                    )
                )
                if link is None:
                    nets[key] = []
                    continue
                try:
                    cidrs = importer.client_for(link.source).allowlist(key[1])
                except ScannerError as e:
                    raise RolloutError(f"Не удалось перечитать allowlist «Сканера»: {e}", 502)
                nets[key] = [ipaddress.ip_network(c, strict=False) for c in cidrs]
            if any(ip in n for n in nets[key]):
                ok = True
                break
        if not ok:
            denied[host] = "вне allowlist проекта «Сканера»"
    return denied


def check_window(db: Session, r: Rollout, hosts: list[str], now=None) -> dict[str, str]:  # noqa: ANN001
    """Хосты, на которых сейчас нельзя менять: вне окна или в блэкаут → причина."""
    now = now or utcnow()
    denied: dict[str, str] = {}
    w = db.get(MaintenanceWindow, r.window_id) if r.window_id else None
    for h in hosts:
        b = windows.blackout_at(db, r.project_id, h, now)
        if b is not None:
            denied[h] = f"блэкаут «{b.name}»"
        elif r.outside_window:
            continue
        elif w is None:
            denied[h] = "окно не задано"
        elif not windows.is_open(db, w, h, now):
            denied[h] = f"окно «{w.name}» сейчас закрыто для хоста"
    return denied


def _dry_run_fresh(r: Rollout) -> bool:
    return r.dry_run_at is not None and utcnow() - as_utc(r.dry_run_at) <= DRY_RUN_TTL


# ---------- пробный прогон, утверждение, запуск, стоп ----------


def request_dry_run(db: Session, r: Rollout, actor: Actor) -> Job:
    if r.status not in ("draft", "pending_approval", "approved"):
        raise RolloutError(f"Пробный прогон недоступен: раскатка «{label(r.status)}»")
    t = db.get(Ticket, r.ticket_id)
    if t is None or t.status in CLOSED_STATUSES:
        raise RolloutError("Заявка закрыта — раскатка не нужна")
    dropped = r.status == "approved"
    r.decided_by = r.decided_at = None
    r.decision_note = ""
    r.allow_reboot = r.outside_window = r.custom_approved = False
    r.outside_window_reason = r.error = ""
    r.dry_run_by = actor.user.id
    _set_status(db, r, "dry_run")
    for h in r.hosts:
        h.status, h.reason, h.dry_status, h.dry_plan, h.dry_note = "pending", "", "", [], ""
    job = jobs.enqueue(
        db,
        "rollout_dry_run",
        {"rollout_id": r.id},
        project_id=r.project_id,
        title=f"Пробный прогон раскатки №{r.id}",
        created_by=actor.user.username,
    )
    r.job_id = job.id
    _audit(db, r, actor.user, "rollout.dry_run", actor.ip, approval_dropped=dropped)
    _history(db, r, actor.user, "rollout_dry_run")
    return job


def approve(
    db: Session,
    r: Rollout,
    actor: Actor,
    *,
    allow_reboot: bool,
    outside_window: bool,
    outside_window_reason: str,
    custom_ack: bool,
    note: str,
) -> None:
    if r.status != "pending_approval":
        raise RolloutError(f"Утверждать нечего: раскатка «{label(r.status)}»")
    if not actor.can(Perm.ROLLOUT_APPROVE):
        raise _denied(r, actor, "rollout.approve", "Утверждает раскатку руководитель")
    if actor.user.id in (r.prepared_by, r.dry_run_by):
        raise _denied(
            r,
            actor,
            "rollout.approve",
            "Четыре глаза: утверждает не тот, кто готовил раскатку или делал пробный прогон",
        )
    if not _dry_run_fresh(r):
        raise RolloutError("Пробный прогон старше 7 дней — повторите его перед утверждением")
    if r.template == "custom" and not custom_ack:
        raise RolloutError("Произвольная команда требует отдельного подтверждения", 422)
    reason = (outside_window_reason or "").strip()
    if outside_window and len(reason) < 3:
        raise RolloutError("Укажите причину запуска вне окна", 422)
    if not outside_window and r.window_id is None:
        raise RolloutError("У раскатки нет окна: разрешите запуск вне окна с причиной", 422)
    r.decided_by, r.decided_at = actor.user.id, utcnow()
    r.decision_note = (note or "").strip()[:2000]
    r.allow_reboot = allow_reboot
    r.outside_window, r.outside_window_reason = outside_window, reason[:1000] if outside_window else ""
    r.custom_approved = r.template == "custom"
    _set_status(db, r, "approved")
    details = {
        "allow_reboot": allow_reboot,
        "outside_window": outside_window,
        "outside_window_reason": r.outside_window_reason,
        "custom_command": r.command if r.template == "custom" else None,
        "note": r.decision_note,
    }
    _audit(db, r, actor.user, "rollout.approve", actor.ip, **details)
    _history(db, r, actor.user, "rollout_approved", _name(actor.user), **details)


def reject(db: Session, r: Rollout, actor: Actor, reason: str) -> None:
    if r.status not in ("pending_approval", "approved"):
        raise RolloutError(f"Отклонять нечего: раскатка «{label(r.status)}»")
    if not actor.can(Perm.ROLLOUT_APPROVE):
        raise _denied(r, actor, "rollout.reject", "Отклоняет раскатку руководитель")
    r.decided_by, r.decided_at, r.decision_note = actor.user.id, utcnow(), reason.strip()[:2000]
    r.finished_at = utcnow()
    _set_status(db, r, "rejected")
    _audit(db, r, actor.user, "rollout.reject", actor.ip, reason=r.decision_note)
    _history(db, r, actor.user, "rollout_rejected", reason=r.decision_note)


def cancel(db: Session, r: Rollout, actor: Actor, reason: str) -> None:
    if r.status not in ("draft", "pending_approval", "approved"):
        raise RolloutError(f"Отменить нельзя: раскатка «{label(r.status)}»")
    own = actor.user.id == r.prepared_by and actor.can(Perm.REMEDIATE_EXECUTE)
    if not own and not actor.can(Perm.ROLLOUT_APPROVE):
        raise _denied(r, actor, "rollout.cancel", "Отменяет раскатку тот, кто её готовил, или руководитель")
    r.stop_reason = reason.strip()[:2000]
    r.finished_at = utcnow()
    _set_status(db, r, "cancelled")
    _audit(db, r, actor.user, "rollout.cancel", actor.ip, reason=r.stop_reason)
    _history(db, r, actor.user, "rollout_cancelled", reason=r.stop_reason)


def running_in_project(db: Session, project_id: str, exclude: int | None = None) -> Rollout | None:
    stmt = select(Rollout).where(Rollout.project_id == project_id, Rollout.status == "running")
    if exclude:
        stmt = stmt.where(Rollout.id != exclude)
    return db.scalar(stmt)


def stages_for(r: Rollout, hosts: list[str]) -> dict[str, int]:
    """Канарейка — этап 0; остальные — партии по batch_percent % от числа хостов (не меньше одного)."""
    rest = [h for h in hosts if h != r.canary_host]
    out: dict[str, int] = {}
    if r.canary_host in hosts:
        out[r.canary_host] = 0
    else:
        rest = list(hosts)
        if rest:
            out[rest.pop(0)] = 0
    size = max(1, math.ceil(len(hosts) * r.batch_percent / 100))
    for i, h in enumerate(rest):
        out[h] = 1 + i // size
    return out


def start(db: Session, r: Rollout, actor: Actor) -> Job:
    """Запуск утверждённой раскатки. Отказы — в журнал аудита отдельной транзакцией."""
    if r.status != "approved":
        raise RolloutError(f"Запуск недоступен: раскатка «{label(r.status)}»")
    if not actor.can(Perm.REMEDIATE_EXECUTE):
        raise _denied(r, actor, "rollout.start", "Запускает раскатку исполнитель с правом «Запуск раскатки на хостах»")
    if actor.user.id == r.decided_by:
        raise _denied(r, actor, "rollout.start", "Четыре глаза: утвердивший раскатку не запускает её сам")
    if not _dry_run_fresh(r):
        raise RolloutError("Пробный прогон старше 7 дней — повторите его и утвердите раскатку заново")
    t = db.get(Ticket, r.ticket_id)
    if t is None or t.status in CLOSED_STATUSES:
        raise RolloutError("Заявка закрыта — раскатка не нужна")
    other = running_in_project(db, r.project_id, exclude=r.id)
    if other is not None:
        raise RolloutError(f"В проекте уже идёт раскатка №{other.id} — дождитесь её окончания")
    try:
        tpl.build_plan(r.template, r.manager, r.packages, r.fixed_version, r.service, r.command)
    except tpl.TemplateError as e:
        raise _denied(r, actor, "rollout.start", f"Параметры раскатки не прошли проверку: {e.message}", 422)
    ready = [h.host for h in r.hosts if h.status == "dry_ok"]
    if not ready:
        raise RolloutError("Нет хостов, прошедших пробный прогон")
    try:
        denied = check_allowlist(db, r, ready)
    except RolloutError as e:
        raise _denied(r, actor, "rollout.start", e.message, e.code)
    denied |= {h: why for h, why in check_window(db, r, ready).items() if h not in denied}
    allowed = [h for h in ready if h not in denied]
    if not allowed:
        raise _denied(
            r,
            actor,
            "rollout.start",
            "Ни один хост сейчас нельзя менять: " + "; ".join(f"{h} — {why}" for h, why in list(denied.items())[:5]),
            409,
            denied=denied,
        )
    stages = stages_for(r, allowed)
    for h in r.hosts:
        if h.host in stages:
            h.status, h.stage, h.reason = "queued", stages[h.host], ""
        elif h.status == "dry_ok":
            h.status, h.reason = "skipped", denied.get(h.host, "")
    if denied:
        _audit(db, r, actor.user, "rollout.denied", actor.ip, result="denied", hosts=denied, stage="start")
    r.started_by, r.started_at = actor.user.id, utcnow()
    r.stop_requested, r.stop_reason, r.stopped_by, r.error = False, "", None, ""
    _set_status(db, r, "running")
    if "in_progress" in workflow.allowed_targets(t, actor) and t.status != "in_progress":
        workflow.change_status(db, t, actor, "in_progress")
    job = jobs.enqueue(
        db,
        "rollout",
        {"rollout_id": r.id},
        project_id=r.project_id,
        title=f"Раскатка №{r.id}",
        created_by=actor.user.username,
    )
    r.job_id = job.id
    details = {"hosts": len(stages), "stages": 1 + max(stages.values()), "skipped": denied}
    _audit(db, r, actor.user, "rollout.start", actor.ip, **details)
    _history(db, r, actor.user, "rollout_started", f"{len(stages)} хост(ов)", **details)
    return job


def request_stop(db: Session, r: Rollout, actor: Actor, reason: str) -> None:
    if r.status not in ("running", "dry_run"):
        raise RolloutError(f"Останавливать нечего: раскатка «{label(r.status)}»")
    if not (actor.can(Perm.REMEDIATE_EXECUTE) or actor.can(Perm.ROLLOUT_APPROVE)):
        raise _denied(
            r, actor, "rollout.stop", "Остановить раскатку может исполнитель с правом запуска или руководитель"
        )
    if r.stop_requested:
        return
    r.stop_requested, r.stopped_by, r.stop_reason = True, actor.user.id, reason.strip()[:2000]
    r.updated_at = utcnow()
    _audit(db, r, actor.user, "rollout.stop", actor.ip, reason=r.stop_reason)
    _history(db, r, actor.user, "rollout_stop", reason=r.stop_reason)


# ---------- исполнение на хосте ----------


class HostFailed(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class HostSession:
    """Подключение к хосту в рамках раскатки: команды через sudo по учётке, каждая — в журнал."""

    db: Session
    r: Rollout
    h: RolloutHost
    phase: str
    conn: object = None
    login: sshexec.Login | None = None
    root: bool = False
    steps: list[RolloutStep] = field(default_factory=list)

    def _wrap(self, argv: list[str], sudo: bool) -> tuple[list[str], str | None]:
        if not sudo or self.root or self.login is None or self.login.become == "none":
            return argv, None
        pw = self.login.sudo_password
        if pw:
            return ["sudo", "-S", "-p", "", *argv], pw + "\n"
        return ["sudo", "-n", *argv], None

    def log(self, label_: str, command: str, res: sshexec.CommandResult | None, ok: bool, error: str = "") -> None:
        tail = 20000
        step = RolloutStep(
            rollout_id=self.r.id,
            rollout_host_id=self.h.id,
            phase=self.phase,
            label=label_[:200],
            command=command[:4000],
            returncode=res.returncode if res else None,
            ok=ok,
            stdout=(res.stdout[-tail:] if res else ""),
            stderr=(res.stderr[-tail:] if res else error[:4000]),
            duration_ms=res.duration_ms if res else 0,
        )
        self.db.add(step)
        self.db.commit()

    async def cmd(
        self,
        label_: str,
        argv: list[str],
        *,
        sudo: bool = True,
        timeout: float = tpl.QUERY_TIMEOUT,
        ok=None,  # noqa: ANN001
        fail: str | None = None,
    ) -> sshexec.CommandResult:
        full, stdin = self._wrap(argv, sudo)
        shown = shlex.join(full)
        try:
            res = await sshexec.run(self.conn, full, stdin=stdin, timeout=timeout)
        except sshexec.SshFailure as e:
            self.log(label_, shown, None, False, e.message)
            raise HostFailed(f"{label_}: {e.message}")
        good = ok(res) if ok else res.returncode == 0
        self.log(label_, shown, res, good)
        if not good and fail is not None:
            detail = (res.stderr or res.stdout).strip().splitlines()
            raise HostFailed(f"{fail} (код {res.returncode}{': ' + detail[-1][:300] if detail else ''})")
        return res


def _stop_requested(db: Session, rollout_id: int) -> bool:
    return bool(db.scalar(select(Rollout.stop_requested).where(Rollout.id == rollout_id)))


async def _connect(s: HostSession, project_id: str) -> None:
    """Учётка по хосту, закреплённый ключ (TOFU), вход и uid. Ошибка — HostFailed."""
    db, h = s.db, s.h
    m = credentials.credential_for_host(db, project_id, h.host)
    if m is None:
        raise HostFailed("Нет SSH-учётки для хоста (раздел «Доступ к хостам»)")
    c = m.credential
    h.credential_id, h.credential_name = c.id, c.name
    hk = credentials.get_host_key(db, project_id, h.host, c.port)
    if hk is not None and hk.status == "mismatch":
        raise HostFailed("Ключ хоста изменился — подключения запрещены, пока руководитель не решит судьбу ключа")
    s.login = credentials.login_for(c)
    started = time.monotonic()
    try:
        conn, key = await sshexec.connect(h.host, c.port, s.login, hk.public_key if hk else None)
    except sshexec.SshFailure as e:
        if e.code == sshexec.HOST_KEY_MISMATCH and hk is not None:
            credentials._record_mismatch(db, hk, e.offered, None, "", "rollout")
        s.log(f"Вход по SSH ({c.username}@{h.host}:{c.port})", "", None, False, e.message)
        raise HostFailed(e.message)
    _, same = credentials.observe_key(db, project_id, h.host, c.port, key, None, "", "rollout")
    if not same:
        conn.close()
        s.log("Ключ хоста", "", None, False, "Ключ хоста не совпал с закреплённым")
        raise HostFailed("Ключ хоста не совпал с закреплённым")
    s.conn = conn
    res = sshexec.CommandResult(0, f"{key.key_type} {key.fingerprint}", "", int((time.monotonic() - started) * 1000))
    s.log(f"Вход по SSH ({c.username}@{h.host}:{c.port})", "", res, True)
    uid = await s.cmd("Пользователь", ["id", "-u"], sudo=False, fail="Не удалось выполнить id")
    s.root = uid.stdout.strip() == "0"


def _versions(s: HostSession, out: str) -> dict[str, str | None]:
    return tpl.parse_versions(s.r.manager, out, list(s.r.packages))


async def _query(s: HostSession, label_: str) -> dict[str, str | None]:
    q = await s.cmd(label_, tpl.query_cmd(s.r.manager, list(s.r.packages)), sudo=False, ok=lambda _r: True)
    return _versions(s, q.stdout)


def _below_fixed(r: Rollout, version: str | None) -> bool:
    return bool(r.fixed_version and version and tpl.compare(r.manager, version, r.fixed_version) < 0)


async def _dry_packages(s: HostSession) -> None:
    r, h = s.r, s.h
    before = await _query(s, "Установленные версии")
    h.versions_before = before
    installed = [p for p, v in before.items() if v]
    if not installed:
        raise HostFailed("Ни один из пакетов раскатки не установлен на хосте")
    if r.template == "kernel":
        k = await s.cmd("Ядро", tpl.KERNEL_CMD, sudo=False, ok=lambda _r: True)
        h.kernel_before = k.stdout.strip()[:200]
    refresh = tpl.refresh_cmd(r.manager)
    if refresh:
        await s.cmd(
            "Обновить списки пакетов", refresh, timeout=tpl.REFRESH_TIMEOUT, fail="Списки пакетов не обновились"
        )
    sim = await s.cmd(
        "Пробный прогон",
        tpl.simulate_cmd(r.manager, installed),
        timeout=tpl.UPGRADE_TIMEOUT,
        ok=lambda res: tpl.simulate_ok(r.manager, res.returncode, res.stdout),
        fail="Менеджер пакетов отказал в пробном режиме",
    )
    plan = tpl.parse_plan(r.manager, sim.stdout)
    h.dry_plan = plan[:200]
    planned = {p["package"]: p["to"] for p in plan}
    notes = []
    missing = [p for p, v in before.items() if not v]
    if missing:
        notes.append(f"не установлены: {', '.join(missing)}")
    for p in installed:
        to = planned.get(p)
        if not r.fixed_version:
            if p not in planned:
                notes.append(f"{p}: обновлений нет")
            continue
        if not _below_fixed(r, before[p]):
            notes.append(f"{p} уже не ниже {r.fixed_version}")
            continue
        if to:
            if _below_fixed(r, to):
                raise HostFailed(f"В репозиториях хоста {p} только {to} — ниже исправленной {r.fixed_version}")
            continue
        if p in planned:  # zypper не показывает версию — проверим после обновления
            notes.append(f"{p}: версия после обновления станет известна при запуске")
            continue
        raise HostFailed(
            f"В репозиториях хоста нет {p} версии {r.fixed_version} или новее (обновление не предлагается)"
        )
    if not plan:
        notes.append("изменений нет")
    h.dry_note = "; ".join(notes)[:2000]


async def _dry_service(s: HostSession) -> None:
    st = await s.cmd("Состояние службы", tpl.service_state_cmd(s.r.service), sudo=False, fail="systemctl не ответил")
    state = tpl.parse_service_state(st.stdout)
    if state.get("LoadState") != "loaded":
        raise HostFailed(f"Служба {s.r.service} не найдена на хосте")
    s.h.versions_before = {s.r.service: state.get("ActiveState", "")}
    await s.cmd("Проверка sudo", ["true"], fail="sudo не сработал")
    s.h.dry_note = f"будет перезапущена служба {s.r.service} (сейчас {state.get('ActiveState', '?')})"


async def _dry_custom(s: HostSession) -> None:
    await s.cmd("Проверка sudo", ["true"], fail="sudo не сработал")
    s.h.dry_note = "У произвольной команды нет пробного режима: проверены вход и sudo"


async def _reboot(s: HostSession) -> None:
    """Перезагрузка и ожидание хоста: тот же закреплённый ключ, новый boot_id."""
    st = get_settings()
    h = s.h
    boot = await s.cmd("Идентификатор загрузки", tpl.BOOT_ID_CMD, sudo=False, ok=lambda _r: True)
    before = boot.stdout.strip()
    full, stdin = s._wrap(tpl.REBOOT_CMD, True)
    try:
        res = await sshexec.run(s.conn, full, stdin=stdin, timeout=30)
        s.log("Перезагрузка", shlex.join(full), res, res.returncode == 0)
        if res.returncode != 0:
            raise HostFailed(f"Перезагрузка не запустилась (код {res.returncode})")
    except sshexec.SshFailure:
        # Соединение рвётся, когда хост уходит в перезагрузку, — это ожидаемо.
        s.log("Перезагрузка", shlex.join(full), None, True, "соединение закрыто хостом")
    s.conn.close()
    s.conn = None
    deadline = time.monotonic() + st.rollout_reboot_timeout_seconds
    started = time.monotonic()
    hk = credentials.get_host_key(s.db, s.r.project_id, h.host, _port(s))
    last = ""
    while time.monotonic() < deadline:
        await asyncio.sleep(st.rollout_reconnect_seconds)
        try:
            conn, _ = await sshexec.connect(h.host, _port(s), s.login, hk.public_key if hk else None, timeout=10)
        except sshexec.SshFailure as e:
            if e.code == sshexec.HOST_KEY_MISMATCH:
                if hk is not None:
                    credentials._record_mismatch(s.db, hk, e.offered, None, "", "rollout")
                s.log("Ожидание после перезагрузки", "", None, False, e.message)
                raise HostFailed(f"После перезагрузки: {e.message}")
            last = e.message
            continue
        s.conn = conn
        now_boot = await s.cmd("Идентификатор загрузки", tpl.BOOT_ID_CMD, sudo=False, ok=lambda _r: True)
        if now_boot.stdout.strip() and now_boot.stdout.strip() != before:
            waited = int((time.monotonic() - started) * 1000)
            s.log("Хост вернулся после перезагрузки", "", sshexec.CommandResult(0, "", "", waited), True)
            h.rebooted = True
            return
        conn.close()
        s.conn = None
    s.log("Ожидание после перезагрузки", "", None, False, last or "хост не ответил")
    raise HostFailed(f"Хост не вернулся после перезагрузки за {st.rollout_reboot_timeout_seconds // 60} мин")


def _port(s: HostSession) -> int:
    c = credentials.credential_for_host(s.db, s.r.project_id, s.h.host)
    return c.credential.port if c else 22


async def _exec_packages(s: HostSession, need_reboot_hint: bool) -> None:
    r, h = s.r, s.h
    before = await _query(s, "Версии «до»")
    h.versions_before = before
    installed = [p for p, v in before.items() if v]
    if not installed:
        raise HostFailed("Ни один из пакетов раскатки не установлен на хосте")
    k = await s.cmd("Ядро «до»", tpl.KERNEL_CMD, sudo=False, ok=lambda _r: True)
    h.kernel_before = k.stdout.strip()[:200]
    s.db.commit()
    refresh = tpl.refresh_cmd(r.manager)
    if refresh:
        await s.cmd(
            "Обновить списки пакетов", refresh, timeout=tpl.REFRESH_TIMEOUT, fail="Списки пакетов не обновились"
        )
    await s.cmd(
        "Обновление",
        tpl.upgrade_cmd(r.manager, installed),
        timeout=tpl.UPGRADE_TIMEOUT,
        fail="Менеджер пакетов завершился с ошибкой",
    )
    after = await _query(s, "Версии «после»")
    h.versions_after = after
    s.db.commit()
    low = [p for p in installed if _below_fixed(r, after.get(p))]
    if low:
        raise HostFailed(
            f"После обновления {', '.join(f'{p} {after.get(p)}' for p in low)} — ниже исправленной {r.fixed_version}"
        )
    need = r.template == "kernel" or need_reboot_hint
    chk = await s.cmd("Нужна ли перезагрузка", tpl.reboot_check_cmd(r.manager), sudo=False, ok=lambda _r: True)
    need = need or bool(tpl.reboot_needed(r.manager, chk.returncode))
    await _maybe_reboot(s, need)


async def _maybe_reboot(s: HostSession, need: bool) -> None:
    h, r = s.h, s.r
    h.reboot_required = need
    if not need:
        return
    if not r.allow_reboot:
        h.status = "reboot_pending"
        h.reason = "нужна перезагрузка — при утверждении она не разрешена"
        return
    if _stop_requested(s.db, r.id):
        h.status = "reboot_pending"
        h.reason = "нужна перезагрузка — не выполнена после аварийного стопа"
        return
    await _reboot(s)
    k = await s.cmd("Ядро «после»", tpl.KERNEL_CMD, sudo=False, ok=lambda _r: True)
    h.kernel_after = k.stdout.strip()[:200]


async def _exec_service(s: HostSession) -> None:
    unit = s.r.service
    st = await s.cmd("Состояние «до»", tpl.service_state_cmd(unit), sudo=False, fail="systemctl не ответил")
    s.h.versions_before = {unit: tpl.parse_service_state(st.stdout).get("ActiveState", "")}
    await s.cmd(
        "Перезапуск службы",
        tpl.service_restart_cmd(unit),
        timeout=tpl.SERVICE_TIMEOUT,
        fail="Служба не перезапустилась",
    )
    act = await s.cmd("Служба работает?", tpl.service_active_cmd(unit), sudo=False, ok=lambda _r: True)
    s.h.versions_after = {unit: act.stdout.strip()[:64]}
    if act.returncode != 0:
        raise HostFailed(f"После перезапуска служба {unit} не активна ({act.stdout.strip()[:64]})")


async def _exec_custom(s: HostSession) -> None:
    await s.cmd("Команда", list(s.r.command), timeout=tpl.CUSTOM_TIMEOUT, fail="Команда завершилась с ошибкой")


async def _host(s: HostSession, sem: asyncio.Semaphore, dry: bool, reboot_hint: bool) -> None:
    db, h, r = s.db, s.h, s.r
    async with sem:
        if not dry and _stop_requested(db, r.id):
            h.status, h.reason = "skipped", "аварийный стоп"
            db.commit()
            return
        h.started_at = utcnow()
        if not dry:
            h.status = "running"
        db.commit()
        t0 = time.monotonic()
        try:
            await _connect(s, r.project_id)
            if r.template in ("package", "kernel"):
                await (_dry_packages(s) if dry else _exec_packages(s, reboot_hint))
            elif r.template == "service":
                await (_dry_service(s) if dry else _exec_service(s))
            else:
                await (_dry_custom(s) if dry else _exec_custom(s))
        except HostFailed as e:
            if dry:
                h.dry_status, h.status, h.reason = "failed", "dry_failed", e.message[:2000]
            else:
                h.status, h.reason = "failed", e.message[:2000]
        except Exception as e:  # noqa: BLE001 — любой сбой хоста — ошибка хоста, не всей раскатки
            msg = f"Внутренняя ошибка: {type(e).__name__}"
            if dry:
                h.dry_status, h.status, h.reason = "failed", "dry_failed", msg
            else:
                h.status, h.reason = "failed", msg
        else:
            if dry:
                h.dry_status, h.status = "ok", "dry_ok"
            elif h.status == "running":
                h.status = "succeeded"
        finally:
            if s.conn is not None:
                s.conn.close()
        h.finished_at = utcnow()
        h.duration_ms = int((time.monotonic() - t0) * 1000)
        if not dry:
            _audit(
                db,
                r,
                None,
                "rollout.host",
                result="ok" if h.status in ("succeeded", "reboot_pending") else "error",
                host=h.host,
                status=h.status,
                reason=h.reason,
                versions_before=h.versions_before,
                versions_after=h.versions_after,
                rebooted=h.rebooted,
                credential=h.credential_name,
            )
        db.commit()


def _parallelism(db: Session, project_id: str) -> int:
    p = db.get(Project, project_id)
    return max(1, min(50, (p.rollout_parallelism if p else 5) or 5))


# ---------- задачи ----------


def execute_dry_run(db: Session, rollout_id: int) -> dict:
    r = db.get(Rollout, rollout_id)
    if r is None:
        raise LookupError("Раскатка не найдена")
    if r.status != "dry_run":
        return rollout_brief(r)
    for h in r.hosts:
        h.status, h.reason, h.dry_status, h.dry_plan, h.dry_note = "pending", "", "", [], ""
    db.query(RolloutStep).filter(RolloutStep.rollout_id == r.id, RolloutStep.phase == "dry_run").delete()
    db.commit()
    hosts = [h.host for h in r.hosts]
    try:
        denied = check_allowlist(db, r, hosts)
    except RolloutError as e:
        r.error = e.message
        _set_status(db, r, "draft")
        _audit(db, r, None, "rollout.dry_run_result", result="error", error=e.message)
        db.commit()
        return rollout_brief(r)
    if denied:
        _audit(db, r, None, "rollout.denied", result="denied", hosts=denied, stage="dry_run")
    for h in r.hosts:
        if h.host in denied:
            h.status, h.dry_status, h.reason = "dry_failed", "failed", denied[h.host]
    db.commit()
    reboot_hint = bool((db.get(Ticket, r.ticket_id).action or {}).get("reboot"))

    async def _all() -> None:
        sem = asyncio.Semaphore(_parallelism(db, r.project_id))
        await asyncio.gather(
            *(_host(HostSession(db, r, h, "dry_run"), sem, True, reboot_hint) for h in r.hosts if h.host not in denied)
        )

    asyncio.run(_all())
    ok = sum(1 for h in r.hosts if h.dry_status == "ok")
    r.dry_run_at = utcnow()
    stopped = _stop_requested(db, r.id)
    if stopped:
        r.stop_requested = False
    if ok and not stopped:
        r.error = ""
        _set_status(db, r, "pending_approval")
    else:
        r.error = "Пробный прогон остановлен" if stopped else "Пробный прогон не прошёл ни на одном хосте"
        _set_status(db, r, "draft")
    counts = {"ok": ok, "failed": sum(1 for h in r.hosts if h.dry_status == "failed")}
    _audit(db, r, None, "rollout.dry_run_result", result="ok" if ok else "error", **counts)
    _history(db, r, None, "rollout_dry_run_result", f"пройден на {ok} из {len(r.hosts)}", **counts)
    db.commit()
    return rollout_brief(r)


def _summary(r: Rollout) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in r.hosts:
        out[h.status] = out.get(h.status, 0) + 1
    return out


def _skip_rest(r: Rollout, reason: str) -> None:
    for h in r.hosts:
        if h.status == "queued":
            h.status, h.reason = "skipped", reason


def execute(db: Session, rollout_id: int) -> dict:
    """Исполнение раскатки: этапы по порядку, проверки allowlist и окна перед каждым этапом."""
    r = db.get(Rollout, rollout_id)
    if r is None:
        raise LookupError("Раскатка не найдена")
    if r.status != "running":
        return rollout_brief(r)
    interrupted = [h for h in r.hosts if h.status == "running"]
    if interrupted:
        for h in interrupted:
            h.status = "failed"
            h.reason = "Служба «Устранения» перезапускалась во время работы с хостом — проверьте хост вручную"
        _skip_rest(r, "раскатка прервана перезапуском службы")
        return _finish(db, r, "failed", "Раскатка прервана перезапуском службы во время работы с хостами")
    reboot_hint = bool((db.get(Ticket, r.ticket_id).action or {}).get("reboot"))
    final, error = "done", ""

    async def _stage(hosts: list[RolloutHost]) -> None:
        sem = asyncio.Semaphore(_parallelism(db, r.project_id))
        await asyncio.gather(*(_host(HostSession(db, r, h, "execute"), sem, False, reboot_hint) for h in hosts))

    for stage in sorted({h.stage for h in r.hosts if h.status == "queued" and h.stage is not None}):
        if _stop_requested(db, r.id):
            final, error = "stopped", ""
            break
        batch = [h for h in r.hosts if h.stage == stage and h.status == "queued"]
        names = [h.host for h in batch]
        try:
            denied = check_allowlist(db, r, names)
        except RolloutError as e:
            final, error = "failed", e.message
            break
        denied |= {h: why for h, why in check_window(db, r, names).items() if h not in denied}
        if denied:
            _audit(db, r, None, "rollout.denied", result="denied", hosts=denied, stage=stage)
            for h in batch:
                if h.host in denied:
                    h.status, h.reason = "skipped", denied[h.host]
        db.commit()
        run_now = [h for h in batch if h.host not in denied]
        if stage == 0 and not run_now:
            final, error = (
                "failed",
                f"Канарейка {names[0]} пропущена ({denied.get(names[0], '')}) — без неё партии не идут",
            )
            break
        asyncio.run(_stage(run_now))
        done = [h for h in r.hosts if h.status in ("succeeded", "reboot_pending", "failed")]
        failed = [h for h in done if h.status == "failed"]
        if stage == 0 and any(h.status == "failed" for h in batch):
            final, error = "failed", f"Канарейка {batch[0].host} не прошла: {batch[0].reason}"
            break
        if done and len(failed) * 100 > r.failure_threshold * len(done):
            pct = round(len(failed) * 100 / len(done))
            final = "failed"
            error = f"Превышен порог ошибок: {len(failed)} из {len(done)} ({pct} %) при пороге {r.failure_threshold} %"
            break
    if _stop_requested(db, r.id) and final == "done" and any(h.status == "queued" for h in r.hosts):
        final = "stopped"
    if final == "stopped":
        _skip_rest(r, "аварийный стоп")
    elif final == "failed":
        _skip_rest(r, "раскатка остановлена: " + error)
    return _finish(db, r, final, error)


def _finish(db: Session, r: Rollout, final: str, error: str) -> dict:
    r.error = error[:2000]
    r.finished_at = utcnow()
    counts = _summary(r)
    _set_status(db, r, final, counts=counts)
    t = db.get(Ticket, r.ticket_id)
    ok_hosts = [h.host for h in r.hosts if h.status == "succeeded"]
    waiting = [h.host for h in r.hosts if h.status == "reboot_pending"]
    failed = [f"{h.host} ({h.reason})" for h in r.hosts if h.status == "failed"]
    parts = [f"Раскатка №{r.id} — {label(final).lower()}: изменение выполнено на {len(ok_hosts)} из {len(r.hosts)}"]
    if waiting:
        parts.append(f"ждут перезагрузки: {', '.join(waiting)}")
    if failed:
        parts.append(f"ошибки: {'; '.join(failed[:10])}")
    if error:
        parts.append(error)
    started_by = db.get(User, r.started_by) if r.started_by else None
    job_ids: list[int] = []
    if ok_hosts and t is not None and t.status not in CLOSED_STATUSES and started_by is not None:
        try:
            items = verification.request(db, t, _actor_of(started_by), ok_hosts, mark_fixed=True)
        except WorkflowError as e:
            parts.append(f"повторная проверка не запущена: {e.message}")
        else:
            r.verification_ids = [v.id for v in items]
            job_ids = [v.result["job_id"] for v in items]
            parts.append("запущена повторная проверка «Сканером»")
    db.add(
        Comment(
            ticket_id=r.ticket_id, author_id=None, kind="system", body="; ".join(parts) + ".", data={"rollout_id": r.id}
        )
    )
    _audit(
        db,
        r,
        None,
        "rollout.finish",
        result="ok" if final == "done" else "error",
        status=final,
        counts=counts,
        error=r.error,
    )
    _history(db, r, None, "rollout_finished", final, counts=counts)
    db.commit()
    for job_id in job_ids:
        jobs.runner.submit(job_id)
    return rollout_brief(r)


@jobs.handler("rollout_dry_run")
def _job_dry_run(db: Session, job: Job) -> dict:
    return execute_dry_run(db, int(job.payload["rollout_id"]))


@jobs.handler("rollout")
def _job_rollout(db: Session, job: Job) -> dict:
    return execute(db, int(job.payload["rollout_id"]))


# ---------- вывод ----------


def rollout_brief(r: Rollout) -> dict:
    return {"id": r.id, "status": r.status, "error": r.error}


def _users(db: Session, ids: set[int | None]) -> dict[int, dict]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {
        u.id: {"id": u.id, "username": u.username, "display_name": u.display_name or u.username}
        for u in db.scalars(select(User).where(User.id.in_(ids)))
    }


def can(r: Rollout, actor: Actor) -> dict:
    uid = actor.user.id
    approver = actor.can(Perm.ROLLOUT_APPROVE)
    executor = actor.can(Perm.REMEDIATE_EXECUTE)
    return {
        "dry_run": executor and r.status in ("draft", "pending_approval", "approved"),
        "approve": approver and r.status == "pending_approval" and uid not in (r.prepared_by, r.dry_run_by),
        "reject": approver and r.status in ("pending_approval", "approved"),
        "start": executor and r.status == "approved" and uid != r.decided_by,
        "stop": (executor or approver) and r.status in ("running", "dry_run") and not r.stop_requested,
        "cancel": r.status in ("draft", "pending_approval", "approved")
        and (approver or (executor and uid == r.prepared_by)),
    }


def stages_out(r: Rollout) -> list[dict]:
    """Этапы для экрана: пробный прогон → утверждение → канарейка → партии → проверка."""
    by_stage: dict[int, list[RolloutHost]] = {}
    for h in r.hosts:
        if h.stage is not None:
            by_stage.setdefault(h.stage, []).append(h)

    def state(hosts: list[RolloutHost]) -> str:
        sts = {h.status for h in hosts}
        if "running" in sts:
            return "running"
        if sts <= {"queued"}:
            return "pending"
        if "failed" in sts:
            return "failed"
        if sts <= {"skipped"}:
            return "skipped"
        if "queued" in sts:
            return "running"
        return "done"

    dry = (
        "running"
        if r.status == "dry_run"
        else ("done" if r.dry_run_at and r.status != "draft" else ("failed" if r.error and r.dry_run_at else "pending"))
    )
    appr = (
        "done"
        if r.decided_at and r.status not in ("rejected",)
        else ("failed" if r.status == "rejected" else ("running" if r.status == "pending_approval" else "pending"))
    )
    out = [
        {"key": "dry_run", "label": "Пробный прогон", "state": dry},
        {"key": "approval", "label": "Утверждение", "state": appr},
    ]
    canary = by_stage.get(0, [])
    out.append(
        {
            "key": "canary",
            "label": "Канарейка",
            "state": state(canary) if canary else "pending",
            "hosts": [h.host for h in canary] or ([r.canary_host] if r.canary_host else []),
        }
    )
    batches = [by_stage[k] for k in sorted(by_stage) if k > 0]
    out.append(
        {
            "key": "batches",
            "label": f"Партии ({len(batches)})" if batches else "Партии",
            "state": ("pending" if not batches else _combine([state(b) for b in batches])),
            "batches": [{"stage": b[0].stage, "hosts": [h.host for h in b], "state": state(b)} for b in batches],
        }
    )
    verify = "pending"
    if r.verification_ids:
        verify = "running"
    if r.status in FINAL and not r.verification_ids and r.started_at:
        verify = "skipped"
    out.append({"key": "verify", "label": "Проверка", "state": verify})
    return out


def _combine(states: list[str]) -> str:
    if "running" in states:
        return "running"
    if "failed" in states:
        return "failed"
    if all(s == "pending" for s in states):
        return "pending"
    if all(s in ("skipped",) for s in states):
        return "skipped"
    if "pending" in states:
        return "running"
    return "done"


def host_out(r: Rollout, h: RolloutHost) -> dict:
    hints = []
    if r.template in ("package", "kernel"):
        for p, v in (h.versions_before or {}).items():
            after = (h.versions_after or {}).get(p)
            if v and after and after != v:
                hints.append(tpl.rollback_hint(r.manager, p, v))
    return {
        "id": h.id,
        "host": h.host,
        "stage": h.stage,
        "status": h.status,
        "status_label": HOST_STATUSES.get(h.status, h.status),
        "reason": h.reason,
        "credential": {"id": h.credential_id, "name": h.credential_name} if h.credential_name else None,
        "dry_status": h.dry_status,
        "dry_plan": h.dry_plan or [],
        "dry_note": h.dry_note,
        "versions_before": h.versions_before or {},
        "versions_after": h.versions_after or {},
        "rollback": [x for x in hints if x],
        "reboot_required": h.reboot_required,
        "rebooted": h.rebooted,
        "kernel_before": h.kernel_before,
        "kernel_after": h.kernel_after,
        "started_at": h.started_at,
        "finished_at": h.finished_at,
        "duration_ms": h.duration_ms,
        "canary": h.host == r.canary_host,
    }


def rollout_out(db: Session, r: Rollout, actor: Actor | None = None, *, detail: bool = False) -> dict:
    users = _users(db, {r.prepared_by, r.dry_run_by, r.decided_by, r.started_by, r.stopped_by})
    t = db.get(Ticket, r.ticket_id)
    w = db.get(MaintenanceWindow, r.window_id) if r.window_id else None
    out = {
        "id": r.id,
        "project_id": r.project_id,
        "ticket": {"id": t.id, "title": t.title, "status": t.status, "os": t.os} if t else None,
        "title": r.title,
        "template": r.template,
        "template_label": tpl.TEMPLATES.get(r.template, r.template),
        "manager": r.manager,
        "packages": r.packages or [],
        "fixed_version": r.fixed_version,
        "service": r.service,
        "command": shlex.join(r.command) if r.command else "",
        "window": {"id": w.id, "name": w.name} if w else None,
        "canary_host": r.canary_host,
        "batch_percent": r.batch_percent,
        "failure_threshold": r.failure_threshold,
        "status": r.status,
        "status_label": label(r.status),
        "error": r.error,
        "note": r.note,
        "prepared_by": users.get(r.prepared_by),
        "dry_run_at": r.dry_run_at,
        "dry_run_by": users.get(r.dry_run_by),
        "decided_by": users.get(r.decided_by),
        "decided_at": r.decided_at,
        "decision_note": r.decision_note,
        "allow_reboot": r.allow_reboot,
        "outside_window": r.outside_window,
        "outside_window_reason": r.outside_window_reason,
        "custom_approved": r.custom_approved,
        "started_by": users.get(r.started_by),
        "started_at": r.started_at,
        "finished_at": r.finished_at,
        "stop_requested": r.stop_requested,
        "stopped_by": users.get(r.stopped_by),
        "stop_reason": r.stop_reason,
        "verification_ids": r.verification_ids or [],
        "counts": _summary(r),
        "hosts_total": len(r.hosts),
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }
    if detail:
        out["hosts"] = [
            host_out(r, h)
            for h in sorted(r.hosts, key=lambda h: (h.stage if h.stage is not None else 999, _ip_key(h.host)))
        ]
        out["stages"] = stages_out(r)
        out["step_counts"] = dict(
            db.execute(
                select(RolloutStep.rollout_host_id, func.count())
                .where(RolloutStep.rollout_id == r.id)
                .group_by(RolloutStep.rollout_host_id)
            ).all()
        )
        out["verifications"] = [
            verification.verification_out(v)
            for v in (db.get(verification.Verification, vid) for vid in r.verification_ids or [])
            if v is not None
        ]
    if actor is not None:
        out["can"] = can(r, actor)
    return out


def step_out(s: RolloutStep) -> dict:
    return {
        "id": s.id,
        "host_id": s.rollout_host_id,
        "phase": s.phase,
        "label": s.label,
        "command": s.command,
        "returncode": s.returncode,
        "ok": s.ok,
        "stdout": s.stdout,
        "stderr": s.stderr,
        "duration_ms": s.duration_ms,
        "at": s.at,
    }
