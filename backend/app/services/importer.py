"""Импорт прогонов «Сканера»: по кнопке и опросом источника.

Импорт идемпотентен по (источник, run_id «Сканера»): повторный импорт того же прогона
ничего не создаёт и возвращает уже сохранённую запись. Прогоны импортируются от старых
к новым — от порядка зависит история появления и исчезновения уязвимостей (задача 1.4).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, jobs
from app.db import as_utc, utcnow
from app.integrations.scanner import FINISHED_STATUSES, ScannerClient, ScannerError, make_client
from app.models import Job, Project, RunCoverage, ScannerSource, ScanRun, SourceLink, User, Verification
from app.security import decrypt_secret

log = logging.getLogger("vm.import")

# Сколько завершённых прогонов просматривать за один опрос привязки.
POLL_WINDOW = 20


def client_for(source: ScannerSource) -> ScannerClient:
    return make_client(source.base_url, source.username, decrypt_secret(source.secret_enc), source.verify_tls)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class RunResults:
    """Результаты прогона, полученные из «Сканера»."""

    meta: dict
    findings: list[dict] = field(default_factory=list)
    fixes: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)


def fetch_results(client: ScannerClient, scanner_run_id: int) -> RunResults:
    meta = client.run(scanner_run_id)
    if meta["status"] not in FINISHED_STATUSES:
        raise ScannerError(f"Прогон {scanner_run_id} ещё не завершён (статус {meta['status']})")
    return RunResults(
        meta, client.findings(scanner_run_id), client.fixes(scanner_run_id), client.coverage(scanner_run_id)
    )


def apply_results(
    db: Session,
    project: Project,
    run: ScanRun,
    results: RunResults,
    *,
    targets: list[str] | None = None,
    strict_tickets: list[int] | None = None,
) -> dict:
    """Перенос результатов в «Устранение»: зеркало уязвимостей и заявки (задача 1.4), закрытие
    исправленного и регрессии по покрытию прогона (задача 1.6), затем правила назначения для
    созданных заявок (задача 2.2)."""
    from app.services import closure, mirror, rules

    stats = mirror.apply(db, project, run, results.findings, results.fixes)
    created = stats.pop("created_ids", [])
    stats |= closure.apply(
        db, project, run, results.findings, results.coverage, targets=targets or [], strict_tickets=strict_tickets or []
    )
    if created:
        stats["tickets_auto_assigned"] = rules.apply(db, project.id, ticket_ids=created)["assigned"]
    return stats


def sync_assets(db: Session, link: SourceLink, client: ScannerClient) -> dict:
    """Активы и группы «Сканера» по привязке (задача 2.2). Ошибка не останавливает импорт:
    заявки важнее, активы обновятся при следующем импорте или по кнопке."""
    from app.services import assets

    try:
        with db.begin_nested():
            st = assets.sync_link(db, link, client)
    except ScannerError as e:
        log.warning("Активы «Сканера» не получены (привязка %s): %s", link.id, e)
        return {"assets_error": str(e)[:300]}
    return {"assets": st["assets"], "assets_removed": st["removed"]}


def import_run(
    db: Session,
    link: SourceLink,
    scanner_run_id: int,
    *,
    actor: User | None = None,
    kind: str = "scheduled",
    client: ScannerClient | None = None,
    targets: list[str] | None = None,
    strict_tickets: list[int] | None = None,
) -> tuple[ScanRun, bool]:
    """Импортирует один прогон. Возвращает (запись прогона, создана ли она сейчас).

    targets и strict_tickets — для прицельной проверки (см. closure.apply)."""
    existing = db.scalar(
        select(ScanRun).where(ScanRun.source_id == link.source_id, ScanRun.scanner_run_id == scanner_run_id)
    )
    if existing:
        return existing, False
    client = client or client_for(link.source)
    results = fetch_results(client, scanner_run_id)
    if results.meta["engagement_id"] != link.engagement_id:
        raise ValueError(f"Прогон {scanner_run_id} относится к другому проекту «Сканера»")
    project = db.get(Project, link.project_id)
    meta = results.meta
    run = ScanRun(
        project_id=link.project_id,
        source_id=link.source_id,
        link_id=link.id,
        scanner_run_id=scanner_run_id,
        engagement_id=link.engagement_id,
        name=meta.get("name") or f"Прогон {scanner_run_id}",
        kind=kind,
        status=meta["status"],
        modules=meta.get("modules", []),
        started_at=_dt(meta.get("started_at")),
        finished_at=_dt(meta.get("finished_at")),
        imported_by=actor.username if actor else "система",
        stats={
            "findings": len(results.findings),
            "fixes": len(results.fixes),
            "hosts": len({c["host"] for c in results.coverage}),
            "hosts_unchecked": len(
                {c["host"] for c in results.coverage if c["status"] not in ("completed", "not_applicable")}
            ),
            "credential_ids": meta.get("credential_ids", []),
            "warnings": [w.get("message", "") for w in meta.get("warnings", []) if isinstance(w, dict)],
        },
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError:
        # Тот же прогон импортировали параллельно — берём сохранённую запись.
        db.rollback()
        existing = db.scalar(
            select(ScanRun).where(ScanRun.source_id == link.source_id, ScanRun.scanner_run_id == scanner_run_id)
        )
        return existing, False
    # Активы — до заявок: правила назначения смотрят на группы, теги и владельцев хостов.
    run.stats = {**run.stats, **sync_assets(db, link, client)}
    for c in results.coverage:
        db.add(
            RunCoverage(
                run_id=run.id, host=c["host"], module=c["module"], status=c["status"], reason=c.get("reason") or ""
            )
        )
    run.stats = {
        **run.stats,
        **apply_results(db, project, run, results, targets=targets, strict_tickets=strict_tickets),
    }
    audit.record(
        db,
        actor,
        "run.import",
        object_type="scan_run",
        object_id=run.id,
        project_id=run.project_id,
        details={
            "scanner_run_id": scanner_run_id,
            "engagement_id": link.engagement_id,
            "kind": kind,
            "status": run.status,
            "findings": len(results.findings),
        },
    )
    return run, True


def pending_runs(db: Session, link: SourceLink, client: ScannerClient) -> list[dict]:
    """Завершённые прогоны привязки, которые ещё не импортированы (от старых к новым).

    Прицельные прогоны, запущенные самим «Устранением», импортирует повторная проверка, а не опрос.
    """
    runs = [r for r in client.runs(link.engagement_id, limit=POLL_WINDOW) if r["status"] in FINISHED_STATUSES]
    known = set(db.scalars(select(ScanRun.scanner_run_id).where(ScanRun.source_id == link.source_id)))
    ours = set(
        db.scalars(
            select(Verification.scanner_run_id).where(
                Verification.source_id == link.source_id, Verification.scanner_run_id.is_not(None)
            )
        )
    )
    todo = [r for r in runs if r["id"] not in known and r["id"] not in ours]
    return sorted(todo, key=lambda r: (r.get("finished_at") or "", r["id"]))


def import_pending(db: Session, link: SourceLink, *, actor: User | None = None) -> list[int]:
    client = client_for(link.source)
    imported = []
    for r in pending_runs(db, link, client):
        run, created = import_run(db, link, r["id"], actor=actor, client=client)
        db.commit()
        if created:
            imported.append(run.id)
    return imported


def due_sources(db: Session) -> list[int]:
    now = utcnow()
    out = []
    for s in db.scalars(select(ScannerSource).where(ScannerSource.auto_import.is_(True))):
        last = as_utc(s.last_poll_at)
        if last is None or now - last >= timedelta(minutes=max(1, s.poll_minutes)):
            out.append(s.id)
    return out


# --- обработчики фоновых задач ---


@jobs.handler("import_run")
def _job_import_run(db: Session, job: Job) -> dict:
    link = db.get(SourceLink, job.payload["link_id"])
    if link is None:
        raise LookupError("Привязка к «Сканеру» удалена")
    actor = db.get(User, job.payload["user_id"]) if job.payload.get("user_id") else None
    run, created = import_run(db, link, int(job.payload["scanner_run_id"]), actor=actor)
    db.commit()
    return {"run_id": run.id, "created": created, "scanner_run_id": run.scanner_run_id}


@jobs.handler("import_pending")
def _job_import_pending(db: Session, job: Job) -> dict:
    actor = db.get(User, job.payload["user_id"]) if job.payload.get("user_id") else None
    imported: list[int] = []
    for link_id in job.payload["link_ids"]:
        link = db.get(SourceLink, link_id)
        if link is not None:
            imported += import_pending(db, link, actor=actor)
    return {"imported": imported}


@jobs.handler("poll_source")
def _job_poll_source(db: Session, job: Job) -> dict:
    source = db.get(ScannerSource, job.payload["source_id"])
    if source is None:
        return {"imported": []}
    source.last_poll_at = utcnow()
    db.commit()
    imported: list[int] = []
    try:
        for link in db.scalars(select(SourceLink).where(SourceLink.source_id == source.id)):
            imported += import_pending(db, link)
        source.last_error = ""
    except (ScannerError, ValueError) as e:
        db.rollback()
        source = db.get(ScannerSource, job.payload["source_id"])
        source.last_error = str(e)[:1000]
        db.commit()
        raise
    db.commit()
    return {"imported": imported}
