"""Автозакрытие по импорту и регрессии (задача 1.6).

Единое правило для плановых и прицельных прогонов: уязвимость на хосте исправлена, только если
в покрытии прогона пара (хост, модуль) — `completed`, а находки с этим dedup_key нет (или её
статус `fixed`). Находка осталась — «не подтверждено». Пара не проверена (`unreachable`, `timeout`,
`no_credentials`, `error`, `skipped`) — «не проверено» с причиной из покрытия, без закрытия.
Прогон, в покрытии которого пары нет вовсе, об этой уязвимости ничего не говорит.

Хост заявки подтверждён, когда исправлены все уязвимости заявки на нём. Все хосты подтверждены —
заявка «Подтверждено» с доказательством. Закрытая уязвимость появилась снова — регрессия:
подтверждённая заявка открывается заново со статусом «Регрессия».

«Строгая» оценка — для заявок, которые проверяют прицельно, и для заявок в статусе «Исправлено,
ждёт проверки»: оставшаяся находка даёт хосту «не подтверждено» (а заявке — возврат в работу),
непроверенный хост — «не проверено» с причиной. В остальных заявках плановый прогон только
закрывает исправленное и отмечает регрессии: работа по ним ещё идёт, помечать её нечего.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import as_utc, utcnow
from app.models import (
    Comment,
    Project,
    ScannerSource,
    ScanRun,
    Ticket,
    TicketHistory,
    Vulnerability,
    VulnerabilityEvent,
)
from app.services.workflow import CLOSED_STATUSES, EXCEPTION_STATUSES, label

COMPLETED = "completed"
COVERAGE_REASONS = {
    "unreachable": "хост недоступен",
    "no_credentials": "нет учётной записи",
    "timeout": "таймаут",
    "error": "ошибка модуля",
    "skipped": "модуль пропущен",
    "not_applicable": "модуль неприменим к хосту",
}

# Итог по уязвимости в прогоне.
FIXED, PRESENT, UNCHECKED, NOT_IN_RUN = "fixed", "present", "unchecked", "not_in_run"


@dataclass
class Outcome:
    result: str
    reason: str = ""


def coverage_reason(status: str, reason: str) -> str:
    base = COVERAGE_REASONS.get(status, status)
    return f"{base}: {reason}" if reason and reason != base else base


def run_url(source: ScannerSource | None, scanner_run_id: int) -> str:
    base = ((source.web_url if source else "") or get_settings().scanner_web_url).rstrip("/")
    return f"{base}/runs/{scanner_run_id}" if base else ""


def evidence(db: Session, run: ScanRun) -> dict:
    """Доказательство закрытия: номер, дата и ссылка на прогон «Сканера»."""
    return {
        "run_id": run.id,
        "scanner_run_id": run.scanner_run_id,
        "run_name": run.name,
        "kind": run.kind,
        "finished_at": as_utc(run.finished_at).isoformat() if run.finished_at else None,
        "url": run_url(db.get(ScannerSource, run.source_id), run.scanner_run_id),
    }


def _label(v: Vulnerability) -> str:
    return v.vuln_id or (v.cve_ids[0] if v.cve_ids else "") or v.title


def _history(db: Session, t: Ticket, action: str, *, from_value="", to_value="", details=None) -> None:
    db.add(
        TicketHistory(
            ticket_id=t.id,
            actor_id=None,
            action=action,
            from_value=str(from_value)[:200],
            to_value=str(to_value)[:200],
            details=details,
        )
    )


def _comment(db: Session, t: Ticket, body: str, data: dict | None = None) -> None:
    db.add(Comment(ticket_id=t.id, author_id=None, kind="system", body=body, data=data))


def set_status(db: Session, t: Ticket, to: str, run: ScanRun, details: dict | None = None) -> None:
    """Перевод статуса системой (импорт, проверка): история, аудит и событие — как у ручного."""
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
    info = {"from": old, "to": to, "run_id": run.id, "scanner_run_id": run.scanner_run_id, **(details or {})}
    _history(db, t, "status", from_value=old, to_value=to, details={"run_id": run.id, "by": "system"})
    audit.record(
        db,
        None,
        "ticket.status",
        object_type="ticket",
        object_id=t.id,
        project_id=t.project_id,
        details={"ticket_id": t.id, **info},
    )
    audit.emit(db, "vm.ticket.status_changed", t.project_id, f"ticket/{t.id}", {"ticket_id": t.id, **info})


def apply(
    db: Session,
    project: Project,
    run: ScanRun,
    findings: list[dict],
    coverage: list[dict],
    *,
    targets: Iterable[str] = (),
    strict_tickets: Iterable[int] = (),
) -> dict:
    """Применяет правило закрытия к уязвимостям и заявкам проекта по результатам прогона.

    targets — цели прицельного прогона: хосты заявок из strict_tickets оцениваются, даже если
    «Сканер» не вернул по ним покрытия (тогда — «не проверено»).
    """
    stats = {
        "vulns_fixed": 0,
        "vulns_regression": 0,
        "vulns_unchecked": 0,
        "tickets_verified": 0,
        "tickets_not_verified": 0,
        "tickets_regression": 0,
    }
    now = utcnow()
    at = run.finished_at or now
    cov = {(c["host"], c["module"]): (c["status"], c.get("reason") or "") for c in coverage}
    present = {f["dedup_key"] for f in findings if f.get("status") != "fixed"}
    targets = set(targets)
    strict_ids = set(strict_tickets)
    hosts = {h for h, _ in cov} | targets
    if not hosts:
        return stats

    # --- уязвимости ---
    outcome: dict[int, Outcome] = {}
    regressed: list[Vulnerability] = []
    vulns = list(
        db.scalars(select(Vulnerability).where(Vulnerability.project_id == project.id, Vulnerability.host.in_(hosts)))
    )
    for v in vulns:
        if v.dedup_key in present:
            outcome[v.id] = Outcome(PRESENT)
            if v.state == "fixed":
                v.state = "open"
                v.is_regression = True
                v.fixed_run_id = None
                v.fixed_at = None
                regressed.append(v)
                stats["vulns_regression"] += 1
                db.add(VulnerabilityEvent(vulnerability_id=v.id, run_id=run.id, event="regression", at=at))
            elif run.kind == "verification":
                db.add(VulnerabilityEvent(vulnerability_id=v.id, run_id=run.id, event="still_present", at=at))
            continue
        pair = cov.get((v.host, v.module))
        if pair is None:
            reason = f"модуль {v.module} на хосте не выполнялся"
            outcome[v.id] = Outcome(FIXED) if v.state == "fixed" else Outcome(NOT_IN_RUN, reason)
            continue
        status, why = pair
        if v.state == "fixed":
            outcome[v.id] = Outcome(FIXED)
            continue
        if status != COMPLETED:
            outcome[v.id] = Outcome(UNCHECKED, coverage_reason(status, why))
            stats["vulns_unchecked"] += 1
            continue
        # Уязвимость видели в более позднем прогоне — старый прогон её не закрывает.
        if run.finished_at and v.last_seen_at and as_utc(v.last_seen_at) > as_utc(run.finished_at):
            outcome[v.id] = Outcome(NOT_IN_RUN, "уязвимость найдена более поздним прогоном")
            continue
        v.state = "fixed"
        v.fixed_run_id = run.id
        v.fixed_at = at
        outcome[v.id] = Outcome(FIXED)
        stats["vulns_fixed"] += 1
        db.add(VulnerabilityEvent(vulnerability_id=v.id, run_id=run.id, event="fixed", at=at))
    db.flush()

    # --- заявки ---
    ticket_ids = {v.ticket_id for v in vulns if v.ticket_id} | strict_ids
    if not ticket_ids:
        return stats
    tickets = list(
        db.scalars(
            select(Ticket)
            .where(Ticket.id.in_(ticket_ids), Ticket.project_id == project.id)
            .order_by(Ticket.id)
            .with_for_update()
        )
    )
    by_ticket: dict[int, list[Vulnerability]] = {}
    for v in db.scalars(select(Vulnerability).where(Vulnerability.ticket_id.in_([t.id for t in tickets]))):
        by_ticket.setdefault(v.ticket_id, []).append(v)
    regressed_ids = {v.id for v in regressed}
    proof = None
    for t in tickets:
        strict = t.id in strict_ids or t.status == "fixed"
        tv = by_ticket.get(t.id, [])
        per_host: dict[str, list[Vulnerability]] = {}
        for v in tv:
            per_host.setdefault(v.host, []).append(v)
        changed = False
        for th in t.hosts:
            hv = per_host.get(th.host, [])
            if not hv:
                continue
            evaluated = any(v.id in outcome and outcome[v.id].result != NOT_IN_RUN for v in hv)
            if not evaluated and not (t.id in strict_ids and th.host in targets):
                continue
            res = [outcome.get(v.id) or Outcome(FIXED if v.state == "fixed" else NOT_IN_RUN) for v in hv]
            left = [_label(v) for v, o in zip(hv, res, strict=True) if o.result == PRESENT]
            again = [_label(v) for v in hv if v.id in regressed_ids]
            if all(o.result == FIXED for o in res):
                new, reason = "confirmed", ""
            elif left and strict:
                new, reason = "not_confirmed", "уязвимость осталась: " + ", ".join(sorted(set(left)))
            elif left and th.status == "confirmed":
                new, reason = "open", "регрессия: " + ", ".join(sorted(set(again or left)))
            elif strict:
                why = sorted({o.reason for o in res if o.result in (UNCHECKED, NOT_IN_RUN) and o.reason})
                new, reason = "unverified", "; ".join(why) or "хост не проверен"
            else:
                th.last_check_run_id = run.id
                continue
            if (th.status, th.reason) != (new, reason):
                th.status, th.reason, th.updated_at = new, reason, now
                changed = True
            th.last_check_run_id = run.id
        if changed:
            t.updated_at = now

        # Регрессия.
        again = sorted({_label(v) for v in tv if v.id in regressed_ids})
        if again:
            t.is_regression = True
            data = {"run_id": run.id, "scanner_run_id": run.scanner_run_id, "vulns": again}
            if t.status == "verified":
                _comment(
                    db,
                    t,
                    f"Регрессия: уязвимости {', '.join(again)} снова найдены прогоном «{run.name}» "
                    f"(№{run.scanner_run_id} «Сканера»). Заявка открыта заново.",
                    data,
                )
                set_status(db, t, "regression", run, {"vulns": again})
                stats["tickets_regression"] += 1
            else:
                note = (
                    f" Заявка в статусе «{label(t.status)}» — статус не меняется."
                    if t.status in EXCEPTION_STATUSES
                    else ""
                )
                _comment(
                    db,
                    t,
                    f"Регрессия: уязвимости {', '.join(again)} снова найдены прогоном «{run.name}» "
                    f"(№{run.scanner_run_id} «Сканера»).{note}",
                    data,
                )
            _history(db, t, "regression", to_value=", ".join(again), details=data)

        if t.status in CLOSED_STATUSES:
            continue
        with_vulns = [th for th in t.hosts if per_host.get(th.host)]
        if with_vulns and all(th.status == "confirmed" for th in with_vulns):
            proof = proof or evidence(db, run)
            t.evidence = proof
            _comment(
                db,
                t,
                f"Исправление подтверждено прогоном «{run.name}» (№{run.scanner_run_id} «Сканера»): "
                f"все хосты заявки ({len(with_vulns)}) проверены, уязвимостей не найдено.",
                {"evidence": proof},
            )
            set_status(db, t, "verified", run)
            audit.emit(
                db,
                "vm.remediation.verified",
                t.project_id,
                f"ticket/{t.id}",
                {"ticket_id": t.id, "run_id": run.id, "scanner_run_id": run.scanner_run_id, "result": "verified"},
            )
            stats["tickets_verified"] += 1
        elif t.status == "fixed" and any(
            th.status == "not_confirmed" and th.last_check_run_id == run.id for th in t.hosts
        ):
            bad = [th for th in t.hosts if th.status == "not_confirmed" and th.last_check_run_id == run.id]
            _comment(
                db,
                t,
                f"Исправление не подтверждено прогоном «{run.name}» (№{run.scanner_run_id} «Сканера»): "
                + "; ".join(f"{th.host} — {th.reason}" for th in bad)
                + ". Заявка возвращена в работу.",
                {"run_id": run.id, "scanner_run_id": run.scanner_run_id, "hosts": [th.host for th in bad]},
            )
            set_status(db, t, "not_verified", run, {"hosts": [th.host for th in bad]})
            audit.emit(
                db,
                "vm.remediation.verified",
                t.project_id,
                f"ticket/{t.id}",
                {"ticket_id": t.id, "run_id": run.id, "scanner_run_id": run.scanner_run_id, "result": "not_verified"},
            )
            stats["tickets_not_verified"] += 1
    db.flush()
    return stats
