"""Повторная проверка заявки прицельным прогоном «Сканера» (задача 1.6).

1. `request()` — по заявке: цели — хосты с открытыми уязвимостями заявки (или выбранные), модули —
   те, что нашли эти уязвимости (плюс `discovery`, если он был в исходном прогоне: без него модуль
   `vuln` не знает портов), `credential_ids` — из прогона, который последним видел уязвимость.
   Хосты из разных проектов «Сканера» дают по прогону на каждый проект.
2. Фоновая задача `verify` запускает прогон (`POST /engagements/{id}/runs`), ждёт завершения,
   импортирует его как прогон вида `verification` и применяет единое правило закрытия
   (app/services/closure.py) в строгом режиме для проверяемой заявки.
3. Цели, отклонённые allowlist «Сканера», получают «не проверено: вне allowlist».

Номер прогона «Сканера» сохраняется сразу после запуска: после рестарта задача не запускает
второй прогон, а продолжает ждать первый. Ожидание не занимает поток пула: пока прогон идёт, задача
откладывает сама себя (`jobs.Defer`) и планировщик вызывает её снова через `VM_VERIFY_POLL_SECONDS`.
Временная ошибка «Сканера» повторяется (app/jobs.py); окончательная переводит проверку в «не выполнена».

Проверка не остаётся «в работе» навсегда:
- окончательный сбой задачи переводит проверку в `failed` (`failed_job`), сверка при старте службы
  делает то же для проверок, чья задача уже не исполняется (`fail_orphaned`);
- проверку можно отменить (`cancel`): статус `cancelled`, прогон «Сканера» останавливается.
"""

import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.config import get_settings
from app.db import as_utc, utcnow
from app.integrations.scanner import FINISHED_STATUSES, ScannerError
from app.models import (
    Comment,
    Job,
    ScanRun,
    SourceLink,
    Ticket,
    TicketHistory,
    TicketHost,
    User,
    Verification,
    Vulnerability,
)
from app.rbac import Perm
from app.services import importer, workflow
from app.services.workflow import CLOSED_STATUSES, Actor, WorkflowError

log = logging.getLogger("vm.verification")

# requested → running → done | failed | cancelled
ACTIVE = ("requested", "running")
# Порядок модулей — как MODULE_ORDER «Сканера» (scanner/core/orchestrator.py).
MODULE_ORDER = ("discovery", "vuln", "auth_inventory", "win_inventory", "config_audit", "password_policy", "cred_audit")


def _order(modules: set[str]) -> list[str]:
    known = [m for m in MODULE_ORDER if m in modules]
    return known + sorted(modules - set(known))


def can_cancel(v: Verification, actor: Actor) -> bool:
    """Отменяет проверку тот, кто её запустил, или руководитель."""
    if v.status not in ACTIVE:
        return False
    return actor.can(Perm.TICKET_ASSIGN) or (actor.can(Perm.VERIFY) and v.requested_by == actor.user.id)


def verification_out(v: Verification, actor: Actor | None = None) -> dict:
    return {
        "id": v.id,
        "ticket_id": v.ticket_id,
        "project_id": v.project_id,
        "source_id": v.source_id,
        "engagement_id": v.engagement_id,
        "scanner_run_id": v.scanner_run_id,
        "run_id": v.run_id,
        "status": v.status,
        "targets": v.targets,
        "denied_targets": v.denied_targets,
        "modules": v.modules,
        "result": v.result,
        "error": v.error,
        "requested_by": v.requested_by,
        "created_at": v.created_at,
        "finished_at": v.finished_at,
        "can_cancel": actor is not None and can_cancel(v, actor),
    }


def active_for(db: Session, ticket_id: int) -> list[Verification]:
    return list(
        db.scalars(select(Verification).where(Verification.ticket_id == ticket_id, Verification.status.in_(ACTIVE)))
    )


def run_name(t: Ticket) -> str:
    return f"Проверка устранения: №{t.id} {t.title}"[:200]


def request(
    db: Session, t: Ticket, actor: Actor, hosts: list[str] | None = None, *, mark_fixed: bool = True
) -> list[Verification]:
    """Ставит повторную проверку заявки. Коммит и запуск задач — у вызывающего кода."""
    if t.status in CLOSED_STATUSES:
        raise WorkflowError(f"Заявка закрыта («{workflow.label(t.status)}»): проверять нечего")
    if active_for(db, t.id):
        raise WorkflowError("Проверка этой заявки уже идёт")
    open_vulns = list(
        db.scalars(select(Vulnerability).where(Vulnerability.ticket_id == t.id, Vulnerability.state == "open"))
    )
    ticket_hosts = {h.host for h in t.hosts}
    if hosts:
        unknown = sorted(set(hosts) - ticket_hosts)
        if unknown:
            raise WorkflowError(f"Хостов нет в заявке: {', '.join(unknown)}", 422)
        open_vulns = [v for v in open_vulns if v.host in set(hosts)]
    if not open_vulns:
        raise WorkflowError("Открытых уязвимостей на выбранных хостах нет — проверять нечего")

    # Группы по проекту «Сканера»: прогон, который последним видел уязвимость.
    runs = {
        r.id: r
        for r in db.scalars(select(ScanRun).where(ScanRun.id.in_({v.last_seen_run_id for v in open_vulns} - {None})))
    }
    groups: dict[tuple[int, int], dict] = {}
    for v in open_vulns:
        r = runs.get(v.last_seen_run_id)
        if r is None:
            raise WorkflowError(f"Не найден прогон, в котором видели уязвимость на {v.host}", 422)
        g = groups.setdefault(
            (r.source_id, r.engagement_id), {"hosts": set(), "modules": set(), "creds": set(), "discovery": False}
        )
        g["hosts"].add(v.host)
        g["modules"].add(v.module)
        g["creds"].update((r.stats or {}).get("credential_ids") or [])
        g["discovery"] = g["discovery"] or "discovery" in (r.modules or [])
    links = {}
    for source_id, engagement_id in groups:
        link = db.scalar(
            select(SourceLink).where(
                SourceLink.project_id == t.project_id,
                SourceLink.source_id == source_id,
                SourceLink.engagement_id == engagement_id,
            )
        )
        if link is None:
            raise WorkflowError(f"Привязка к проекту «Сканера» №{engagement_id} удалена — проверка невозможна", 422)
        links[(source_id, engagement_id)] = link

    # «Исправлено — проверить»: если исполнитель может перевести заявку в «Исправлено», переводим.
    if mark_fixed and t.status != "fixed" and "fixed" in workflow.allowed_targets(t, actor):
        workflow.change_status(db, t, actor, "fixed")

    out = []
    for (source_id, engagement_id), g in groups.items():
        modules = set(g["modules"]) | ({"discovery"} if g["discovery"] else set())
        v = Verification(
            ticket_id=t.id,
            project_id=t.project_id,
            source_id=source_id,
            engagement_id=engagement_id,
            status="requested",
            targets=sorted(g["hosts"]),
            modules=_order(modules),
            result={"credential_ids": sorted(g["creds"])},
            requested_by=actor.user.id,
        )
        db.add(v)
        db.flush()
        out.append(v)
        details = {
            "verification_id": v.id,
            "engagement_id": engagement_id,
            "targets": v.targets,
            "modules": v.modules,
        }
        db.add(
            TicketHistory(
                ticket_id=t.id,
                actor_id=actor.user.id,
                action="verify_requested",
                to_value=f"{len(v.targets)} хост(ов)",
                details=details,
            )
        )
        audit.record(
            db,
            actor.user,
            "ticket.verify",
            object_type="ticket",
            object_id=t.id,
            project_id=t.project_id,
            ip=actor.ip,
            details={"ticket_id": t.id, **details},
        )
        job = jobs.enqueue(
            db,
            "verify",
            {"verification_id": v.id},
            project_id=t.project_id,
            title=f"Проверка заявки №{t.id}",
            created_by=actor.user.username,
        )
        v.result = {**v.result, "job_id": job.id}
    workflow.watch(db, t, actor.user)
    t.updated_at = utcnow()
    return out


# --- исполнение ---


def _mark_denied(db: Session, v: Verification, denied: list[dict]) -> list[dict]:
    """Цели вне allowlist «Сканера» — «не проверено» с причиной."""
    out = []
    by_host = {h.host: h for h in db.scalars(select(TicketHost).where(TicketHost.ticket_id == v.ticket_id))}
    for d in denied:
        target = str(d.get("target", ""))
        reason = f"вне allowlist «Сканера»: {d.get('reason') or 'цель не разрешена'}"
        th = by_host.get(target)
        if th is not None:
            th.status, th.reason, th.updated_at = "unverified", reason, utcnow()
        out.append({"host": target, "status": "unverified", "reason": reason})
    return out


def _comment(db: Session, ticket_id: int, body: str, data: dict) -> None:
    db.add(Comment(ticket_id=ticket_id, author_id=None, kind="system", body=body, data=data))


def _finish(db: Session, v: Verification, hosts: list[dict], run: ScanRun | None) -> None:
    t = db.get(Ticket, v.ticket_id)
    counts = {s: sum(1 for h in hosts if h["status"] == s) for s in ("confirmed", "not_confirmed", "unverified")}
    v.status = "done"
    v.finished_at = utcnow()
    v.result = {**(v.result or {}), "hosts": hosts, "counts": counts, "ticket_status": t.status if t else None}
    if run is not None:
        v.run_id = run.id
    if t is None:
        return
    head = (
        f"Повторная проверка (прогон №{v.scanner_run_id} «Сканера»)"
        if v.scanner_run_id
        else "Повторная проверка не запущена"
    )
    parts = [f"подтверждено {counts['confirmed']} из {len(hosts)}"]
    bad = [h for h in hosts if h["status"] != "confirmed"]
    parts += [
        f"{h['host']} — {'не подтверждено' if h['status'] == 'not_confirmed' else 'не проверено'}"
        + (f" ({h['reason']})" if h["reason"] else "")
        for h in bad
    ]
    _comment(db, t.id, f"{head}: " + "; ".join(parts) + ".", {"verification_id": v.id, "counts": counts})
    result = (
        "verified"
        if t.status == "verified"
        else ("not_verified" if counts["not_confirmed"] else ("partial" if counts["confirmed"] else "unverified"))
    )
    v.result["outcome"] = result
    db.add(
        TicketHistory(
            ticket_id=t.id,
            actor_id=None,
            action="verify_result",
            to_value=result,
            details={"verification_id": v.id, "counts": counts, "run_id": v.run_id},
        )
    )
    audit.record(
        db,
        None,
        "ticket.verify_result",
        object_type="ticket",
        object_id=t.id,
        project_id=t.project_id,
        details={"ticket_id": t.id, "verification_id": v.id, "result": result, "counts": counts},
    )
    # Итог «подтверждено» и «не подтверждено» уже отправлен правилом закрытия.
    if result not in ("verified", "not_verified"):
        audit.emit(
            db,
            "vm.remediation.verified",
            t.project_id,
            f"ticket/{t.id}",
            {"ticket_id": t.id, "run_id": v.run_id, "scanner_run_id": v.scanner_run_id, "result": result},
        )


def _fail(db: Session, v: Verification, message: str) -> None:
    v.status = "failed"
    v.error = message[:1000]
    v.finished_at = utcnow()
    _comment(db, v.ticket_id, f"Повторная проверка не выполнена: {message}", {"verification_id": v.id})
    audit.record(
        db,
        None,
        "ticket.verify_result",
        object_type="ticket",
        object_id=v.ticket_id,
        project_id=v.project_id,
        result="error",
        details={"ticket_id": v.ticket_id, "verification_id": v.id, "error": message[:500]},
    )


def _locked(db: Session, verification_id: int) -> Verification | None:
    """Проверка под блокировкой строки со свежим статусом: отмена и итог не перетирают друг друга."""
    return db.scalars(
        select(Verification)
        .where(Verification.id == verification_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()


def _stop_run(client, scanner_run_id: int) -> str:  # noqa: ANN001
    """Просит «Сканер» остановить прогон. Возвращает текст ошибки или пустую строку."""
    try:
        client.stop_run(scanner_run_id)
    except ScannerError as e:
        log.warning("Прогон %s «Сканера» не остановлен: %s", scanner_run_id, e)
        return str(e)
    return ""


def execute(db: Session, verification_id: int) -> dict:
    """Один шаг проверки: запустить прогон, если ещё не запущен, и, если он завершён, импортировать.

    Пока прогон идёт, бросает `jobs.Defer` — задача `verify` вызовет шаг снова, не занимая поток."""
    s = get_settings()
    v = db.get(Verification, verification_id, populate_existing=True)
    if v is None:
        raise LookupError("Проверка не найдена")
    if v.status not in ACTIVE:
        return verification_out(v)
    link = db.scalar(
        select(SourceLink).where(
            SourceLink.project_id == v.project_id,
            SourceLink.source_id == v.source_id,
            SourceLink.engagement_id == v.engagement_id,
        )
    )
    if link is None:
        _fail(db, v, "привязка к проекту «Сканера» удалена")
        db.commit()
        return verification_out(v)
    client = importer.client_for(link.source)
    t = db.get(Ticket, v.ticket_id)

    if v.scanner_run_id is None:
        body = {
            "targets": v.targets,
            "modules": v.modules,
            "credential_ids": (v.result or {}).get("credential_ids", []),
            "rate_profile": "gentle",
            "name": run_name(t) if t else f"Проверка устранения: {v.id}",
        }
        try:
            created = client.start_run(v.engagement_id, body)
        except ScannerError as e:
            detail = e.detail if isinstance(e.detail, dict) else {}
            if e.status == 422 and "denied_targets" in detail:
                v.denied_targets = detail["denied_targets"]
                hosts = _mark_denied(db, v, v.denied_targets)
                _finish(db, v, hosts, None)
                db.commit()
                return verification_out(v)
            # Временную ошибку задача повторит; окончательную доведёт до статуса failed_job().
            raise
        v = _locked(db, verification_id)
        v.scanner_run_id = int(created["id"])
        v.denied_targets = created.get("denied_targets") or []
        if v.status not in ACTIVE:
            # Проверку отменили, пока «Сканер» принимал запуск: прогон не нужен.
            db.commit()
            _stop_run(client, v.scanner_run_id)
            return verification_out(v)
        v.status = "running"
        _mark_denied(db, v, v.denied_targets)
        db.commit()

    # Прогон ещё идёт — не ждём в потоке: задача вернётся сюда через verify_poll_seconds.
    meta = client.run(v.scanner_run_id)
    if meta["status"] not in FINISHED_STATUSES:
        deadline = as_utc(v.created_at) + timedelta(minutes=s.verify_timeout_minutes)
        if utcnow() > deadline:
            _fail(db, v, f"прогон №{v.scanner_run_id} не завершился за {s.verify_timeout_minutes} мин")
            db.commit()
            return verification_out(v)
        raise jobs.Defer(s.verify_poll_seconds)

    # Импорт и итог — под блокировкой проверки: отмена и итог не перетирают друг друга.
    v = _locked(db, verification_id)
    if v.status not in ACTIVE:
        db.rollback()
        return verification_out(v)
    actor = db.get(User, v.requested_by) if v.requested_by else None
    denied = {str(d.get("target")) for d in v.denied_targets}
    run, _ = importer.import_run(
        db,
        link,
        v.scanner_run_id,
        actor=actor,
        kind="verification",
        client=client,
        targets=[h for h in v.targets if h not in denied],
        strict_tickets=[v.ticket_id],
    )
    db.flush()
    by_host = {h.host: h for h in db.scalars(select(TicketHost).where(TicketHost.ticket_id == v.ticket_id))}
    hosts = []
    for host in v.targets:
        th = by_host.get(host)
        if th is None:
            continue
        status = th.status if th.status in ("confirmed", "not_confirmed", "unverified") else "unverified"
        hosts.append({"host": host, "status": status, "reason": th.reason, "denied": host in denied})
    _finish(db, v, hosts, run)
    db.commit()
    return verification_out(v)


# --- отмена и сбои задачи ---


def cancel(db: Session, verification_id: int, actor: Actor, reason: str = "") -> Verification | None:
    """Отменяет идущую проверку и просит «Сканер» остановить прогон. Коммит — здесь.

    Заявка остаётся в своём статусе: проверку можно запустить заново."""
    v = _locked(db, verification_id)
    if v is None:
        return None
    if v.status not in ACTIVE:
        raise WorkflowError("Отменять нечего: проверка уже завершена")
    if not can_cancel(v, actor):
        raise WorkflowError("Отменить проверку может тот, кто её запустил, или руководитель", 403)
    reason = reason.strip()[:1000]
    v.status = "cancelled"
    v.finished_at = utcnow()
    v.result = {**(v.result or {}), "cancelled_by": actor.user.id, "cancel_reason": reason}
    details = {"verification_id": v.id, "scanner_run_id": v.scanner_run_id, "reason": reason}
    db.add(
        TicketHistory(
            ticket_id=v.ticket_id, actor_id=actor.user.id, action="verify_cancelled", to_value="", details=details
        )
    )
    audit.record(
        db,
        actor.user,
        "ticket.verify_cancel",
        object_type="ticket",
        object_id=v.ticket_id,
        project_id=v.project_id,
        ip=actor.ip,
        details={"ticket_id": v.ticket_id, **details},
    )
    db.commit()

    # Статус уже сохранён: дальше — остановка прогона, её сбой отмену не отменяет.
    who = actor.user.display_name or actor.user.username
    text = f"Повторная проверка отменена ({who})" + (f": {reason}" if reason else "")
    if v.scanner_run_id is not None:
        link = db.scalar(
            select(SourceLink).where(
                SourceLink.project_id == v.project_id,
                SourceLink.source_id == v.source_id,
                SourceLink.engagement_id == v.engagement_id,
            )
        )
        error = _stop_run(importer.client_for(link.source), v.scanner_run_id) if link else "привязка удалена"
        if error:
            text += f". Прогон №{v.scanner_run_id} остановить не удалось ({error}) — остановите его в «Сканере»"
            v.result = {**v.result, "stop_error": error[:500]}
        else:
            text += f". Прогон №{v.scanner_run_id} «Сканера» остановлен"
    _comment(db, v.ticket_id, text + ".", {"verification_id": v.id})
    db.commit()
    return v


@jobs.on_recover
def fail_orphaned(db: Session) -> list[int]:
    """Сверка при старте: активные проверки, чья задача уже не исполняется, получают статус failed."""
    out = []
    for v in db.scalars(select(Verification).where(Verification.status.in_(ACTIVE))):
        job_id = (v.result or {}).get("job_id")
        if jobs.alive(db, job_id):
            continue
        job = db.get(Job, job_id) if job_id else None
        why = f" ({job.error})" if job and job.error else ""
        _fail(db, v, f"задача проверки прервана{why} — запустите проверку заново")
        out.append(v.id)
    return out


def failed_job(db: Session, job: Job, e: Exception) -> None:
    """Задача проверки провалилась окончательно — проверка не остаётся висеть в «идёт»."""
    v = _locked(db, int(job.payload["verification_id"]))
    if v is not None and v.status in ACTIVE:
        _fail(db, v, jobs.safe_error(e))


@jobs.handler("verify", on_failed=failed_job)
def _job_verify(db: Session, job: Job) -> dict:
    out = execute(db, int(job.payload["verification_id"]))
    return {"verification_id": out["id"], "status": out["status"], "scanner_run_id": out["scanner_run_id"]}
