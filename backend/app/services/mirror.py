"""Зеркало уязвимостей и заявки из действий «Что исправить» (задача 1.4).

- Уязвимость — по ключу (проект, dedup_key): последние данные находки из «Сканера» и история
  появления по прогонам.
- Заявка — по ключу (проект, fixes[].key): одна заявка на действие исправления в рамках проекта
  и ОС, подзадачи — по хостам. Новые хосты дописываются в существующую заявку.
- Закрытие исправленного и регрессии — app/services/closure.py (задача 1.6), сразу после зеркала.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import utcnow
from app.models import Comment, Project, ScanRun, Ticket, TicketHistory, TicketHost, Vulnerability, VulnerabilityEvent

# Вид действия «Сканера» → вид заявки.
KIND_MAP = {
    "package": "package",
    "package_upgrade": "package",
    "package_nofix": "package",
    "kernel": "kernel",
    "software": "software",
    "config": "config",
    "cred": "account",
    "vuln": "other",
    "other": "other",
}
KIND_LABELS = {
    "package": "Пакет",
    "kernel": "Ядро",
    "software": "ПО",
    "config": "Конфигурация",
    "account": "Учётная запись",
    "other": "Прочее",
}
# Заявка в этих статусах не меняет статус от импорта (закрытые и исключения — задачи 1.6 и этап 2).
CLOSED_STATUSES = {"verified", "risk_accepted", "false_positive"}


def ticket_title(fix: dict) -> str:
    """Название как в ТЗ: «Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3»."""
    pkgs = ", ".join(fix.get("packages") or [])
    os_ = fix.get("os")
    if fix["kind"] in ("package", "package_upgrade") and pkgs and os_:
        ver = f" до {fix['fixed_version']}" if fix.get("fixed_version") else ""
        return f"Обновить {pkgs} на {os_}{ver}"
    title = fix.get("title") or "Действие без названия"
    if os_ and os_ not in title:
        title = f"{title} ({os_})"
    return title[:500]


def _action(fix: dict) -> dict:
    keys = (
        "kind_label",
        "manager",
        "packages",
        "fixed_version",
        "software",
        "steps",
        "commands",
        "verify",
        "reboot",
        "details",
        "details_source",
        "cves",
        "bdu_ids",
        "advisories",
        "references",
    )
    return {**{k: fix.get(k) for k in keys}, "scanner_title": fix.get("title")}


def _history(
    db: Session, ticket: Ticket, action: str, *, from_value: str = "", to_value: str = "", details: dict | None = None
) -> None:
    db.add(
        TicketHistory(
            ticket_id=ticket.id, actor_id=None, action=action, from_value=from_value, to_value=to_value, details=details
        )
    )


def _system_comment(db: Session, ticket: Ticket, body: str, data: dict | None = None) -> None:
    db.add(Comment(ticket_id=ticket.id, author_id=None, kind="system", body=body, data=data))


def apply(db: Session, project: Project, run: ScanRun, findings: list[dict], fixes: list[dict]) -> dict:
    stats = {
        "vulns_new": 0,
        "vulns_seen": 0,
        "vulns_skipped": 0,
        "tickets_created": 0,
        "tickets_updated": 0,
        "ticket_hosts_added": 0,
    }
    now = utcnow()

    # --- зеркало уязвимостей ---
    existing = {v.dedup_key: v for v in db.scalars(select(Vulnerability).where(Vulnerability.project_id == project.id))}
    by_finding_id: dict[int, Vulnerability] = {}
    appeared: list[Vulnerability] = []
    for f in findings:
        # Ложные срабатывания и информационные находки в работу не берутся («Сканер» не включает их в план).
        if f.get("false_positive") or f.get("severity") == "info":
            stats["vulns_skipped"] += 1
            continue
        v = existing.get(f["dedup_key"])
        if v is None:
            v = Vulnerability(
                project_id=project.id,
                dedup_key=f["dedup_key"],
                first_seen_run_id=run.id,
                first_seen_at=run.finished_at or now,
                state="open",
            )
            db.add(v)
            existing[f["dedup_key"]] = v
            stats["vulns_new"] += 1
            new = True
        else:
            stats["vulns_seen"] += 1
            new = False
        prio = f.get("priority") or {}
        v.scanner_finding_id = f["id"]
        v.source_id = run.source_id
        v.host = f["host"]
        v.port = f.get("port")
        v.module = f["module"]
        v.finding_type = f.get("finding_type") or "vuln"
        v.title = (f.get("title") or "")[:500]
        v.severity = f.get("severity") or "info"
        v.priority = {k: prio.get(k) for k in ("rank", "score", "label", "label_ru", "reasons")} if prio else {}
        v.vuln_id = f.get("vuln_id") or ""
        v.cve_ids = f.get("cve_ids") or []
        v.bdu_ids = f.get("bdu_ids") or []
        v.cvss = f.get("cvss")
        v.software = f.get("software") or ""
        v.software_version = f.get("software_version") or ""
        v.confidence = f.get("confidence") or ""
        v.scanner_status = f.get("status") or ""
        v.last_seen_run_id = run.id
        v.last_seen_at = run.finished_at or now
        if new:
            appeared.append(v)
        by_finding_id[f["id"]] = v
    db.flush()  # один flush на прогон: id новых уязвимостей нужны для истории
    for v in appeared:
        db.add(VulnerabilityEvent(vulnerability_id=v.id, run_id=run.id, event="appeared", at=v.last_seen_at))

    # --- заявки из действий исправления ---
    tickets = {
        t.fix_key: t
        for t in db.scalars(select(Ticket).where(Ticket.project_id == project.id, Ticket.fix_key.is_not(None)))
    }
    for fix in fixes:
        vulns = [by_finding_id[ref["id"]] for h in fix["hosts"] for ref in h["findings"] if ref["id"] in by_finding_id]
        if not vulns:
            continue
        t = tickets.get(fix["key"])
        created = t is None
        prio = fix.get("priority") or {}
        if t is None:
            nofix = fix["kind"] == "package_nofix"
            t = Ticket(
                project_id=project.id,
                fix_key=fix["key"],
                title=ticket_title(fix),
                kind=KIND_MAP.get(fix["kind"], "other"),
                scanner_kind=fix["kind"],
                os=fix.get("os") or "",
                os_family=fix.get("os_family") or "",
                status="no_vendor_fix" if nofix else "new",
                created_at=now,
                updated_at=now,
            )
            db.add(t)
            db.flush()
            tickets[fix["key"]] = t
            stats["tickets_created"] += 1
            _history(
                db, t, "created", to_value=t.status, details={"run_id": run.id, "scanner_run_id": run.scanner_run_id}
            )
            audit.emit(
                db,
                "vm.ticket.created",
                project.id,
                f"ticket/{t.id}",
                {"ticket_id": t.id, "title": t.title, "severity": fix.get("severity"), "fix_key": t.fix_key},
            )
        else:
            stats["tickets_updated"] += 1
            t.title = ticket_title(fix)
            t.updated_at = now
        t.severity = fix.get("severity") or "info"
        t.priority_rank = prio.get("rank")
        t.priority_label = prio.get("label") or ""
        t.action = _action(fix)
        # Подзадачи по хостам.
        hosts = {h.host: h for h in t.hosts}
        for h in fix["hosts"]:
            th = hosts.get(h["host"])
            if th is None:
                th = TicketHost(ticket_id=t.id, host=h["host"], status="open", updated_at=now)
                db.add(th)
                t.hosts.append(th)
                hosts[h["host"]] = th
                stats["ticket_hosts_added"] += 1
                if not created:
                    _history(db, t, "host_added", to_value=h["host"], details={"run_id": run.id})
            th.installed = h.get("installed") or ""
            th.note = h.get("note") or ""
        # Связь уязвимостей с заявкой. Если уязвимость ушла из заявки «Нет исправления» в заявку
        # с обновлением — производитель выпустил исправление: пишем об этом в старую заявку.
        moved_from: dict[int, list[str]] = {}
        for v in vulns:
            if v.ticket_id and v.ticket_id != t.id:
                moved_from.setdefault(v.ticket_id, []).append(v.cve_ids[0] if v.cve_ids else v.title)
            v.ticket_id = t.id
            v.fix_key = fix["key"]
        for old_id, labels in moved_from.items():
            old = db.get(Ticket, old_id)
            if old is None:
                continue
            if old.scanner_kind == "package_nofix":
                body = (
                    f"Производитель выпустил исправление: {', '.join(sorted(set(labels)))}. "
                    f"Уязвимости перенесены в заявку №{t.id} «{t.title}»."
                )
            else:
                body = (
                    f"Уязвимости {', '.join(sorted(set(labels)))} перенесены в заявку №{t.id} «{t.title}»: "
                    "«Сканер» изменил состав действия исправления."
                )
            _system_comment(db, old, body, {"moved_to": t.id, "run_id": run.id})
            _history(db, old, "vulns_moved", to_value=str(t.id), details={"count": len(labels), "run_id": run.id})
    db.flush()
    return stats
