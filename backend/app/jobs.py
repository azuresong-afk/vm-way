"""Фоновые задачи в процессе API: пул потоков, состояние — в таблице jobs.

Задача сначала записывается в БД (queued), затем исполняется в пуле. При старте процесса
незавершённые задачи (queued/running) возвращаются в очередь — работа переживает рестарт.
Сбой задачи не оставляет связанный объект (проверку, раскатку) «в работе»: обработчик сбоя
(`on_failure`) переводит его в конечный статус, а сверка при старте (`on_recover`) делает то же
для объектов, чья задача уже не исполняется.
Опросчик раз в минуту ставит в очередь опрос источников, у которых подошёл срок, и закрывает
исключения с прошедшей датой пересмотра.
"""

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import SessionLocal, utcnow
from app.models import Job

log = logging.getLogger("vm.jobs")

Handler = Callable[[Session, Job], dict | None]
_handlers: dict[str, Handler] = {}
MAX_ATTEMPTS = 3
# Задача в одном из этих статусов ещё исполняется или будет исполнена.
ALIVE = ("queued", "running")

FailureHook = Callable[[Session, Job, str], None]
RecoverHook = Callable[[Session], object]
_failure_hooks: dict[str, FailureHook] = {}
_recover_hooks: list[RecoverHook] = []


def handler(kind: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        _handlers[kind] = fn
        return fn

    return deco


def on_failure(*kinds: str) -> Callable[[FailureHook], FailureHook]:
    """Обработчик сбоя задачи: вызывается после записи статуса failed, в своей транзакции.

    Его дело — довести до конечного статуса объект, который вела задача."""

    def deco(fn: FailureHook) -> FailureHook:
        for kind in kinds:
            _failure_hooks[kind] = fn
        return fn

    return deco


def on_recover(fn: RecoverHook) -> RecoverHook:
    """Сверка при старте службы: объекты «в работе», чья задача уже не исполняется."""
    _recover_hooks.append(fn)
    return fn


def alive(db: Session, job_id: int | None) -> bool:
    job = db.get(Job, job_id) if job_id else None
    return job is not None and job.status in ALIVE


class JobRunner:
    def __init__(self, workers: int = 4, inline: bool = False):
        self.inline = inline
        self._workers = workers
        self._pool: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._poller: threading.Thread | None = None

    # --- жизненный цикл ---
    def start(self, poll: bool = True) -> None:
        if not self.inline:
            self._pool = ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="vm-job")
        self._stop.clear()
        self.recover()
        if poll:
            self._poller = threading.Thread(target=self._poll_loop, name="vm-poller", daemon=True)
            self._poller.start()

    def stop(self) -> None:
        self._stop.set()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def recover(self) -> None:
        """Незавершённые задачи после рестарта — снова в очередь."""
        with SessionLocal() as db:
            ids = []
            for job in db.scalars(select(Job).where(Job.status.in_(["queued", "running"]))):
                if job.status == "running":
                    job.status = "queued"
                    job.error = "Служба перезапускалась — задача поставлена в очередь заново"
                ids.append(job.id)
            db.commit()
            for hook in _recover_hooks:
                try:
                    hook(db)
                    db.commit()
                except Exception:  # noqa: BLE001 — сбой сверки не мешает старту службы
                    db.rollback()
                    log.exception("Сбой сверки незавершённых объектов (%s)", hook.__name__)
        for job_id in ids:
            self.submit(job_id)

    # --- постановка и исполнение ---
    def submit(self, job_id: int) -> None:
        if self.inline or self._pool is None:
            self.run(job_id)
        else:
            self._pool.submit(self.run, job_id)

    def run(self, job_id: int) -> None:
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job is None or job.status not in ("queued",):
                return
            fn = _handlers.get(job.kind)
            job.status = "running"
            job.started_at = utcnow()
            job.attempts += 1
            db.commit()
            try:
                if fn is None:
                    raise RuntimeError(f"нет обработчика задачи {job.kind}")
                result = fn(db, job)
                db.refresh(job)
                job.status, job.result, job.error = "done", result or {}, ""
                job.finished_at = utcnow()
                db.commit()
                return
            except Exception as e:  # noqa: BLE001 — любая ошибка задачи пишется в её запись
                log.warning("Задача %s (%s) завершилась ошибкой: %s", job_id, job.kind, e)
                error = _safe_error(e)
        self._failed(job_id, error)

    def _failed(self, job_id: int, error: str) -> None:
        """Запись сбоя — в новой сессии: прежняя могла остаться без соединения с БД."""
        try:
            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job is None:
                    return
                job.status, job.error, job.finished_at = "failed", error, utcnow()
                db.commit()
                hook = _failure_hooks.get(job.kind)
                if hook is None:
                    return
                try:
                    hook(db, job, error)
                    db.commit()
                except Exception:  # noqa: BLE001
                    db.rollback()
                    log.exception("Сбой обработчика ошибки задачи %s (%s)", job_id, job.kind)
        except Exception:  # noqa: BLE001 — БД недоступна: задачу и её объект подберёт сверка при старте
            log.exception("Не удалось записать сбой задачи %s", job_id)

    def _poll_loop(self) -> None:
        from app.services.importer import due_sources

        while True:
            try:
                with SessionLocal() as db:
                    for source_id in due_sources(db):
                        job = enqueue(db, "poll_source", {"source_id": source_id}, title="Опрос «Сканера»", dedupe=True)
                        db.commit()
                        if job:
                            self.submit(job.id)
            except Exception:  # noqa: BLE001
                log.exception("Сбой опроса источников")
            self._expire_exceptions()
            if self._stop.wait(60):
                return

    def _expire_exceptions(self) -> None:
        """Исключения, у которых прошла дата пересмотра, истекают (задача 2.5)."""
        from app.services.exceptions import expire_due

        try:
            with SessionLocal() as db:
                expired = expire_due(db)
                db.commit()
                for job in expired:
                    self.submit(job.id)
        except Exception:  # noqa: BLE001
            log.exception("Сбой проверки дат пересмотра исключений")


def _safe_error(e: Exception) -> str:
    from app.integrations.scanner import ScannerError

    if isinstance(e, ScannerError | ValueError | LookupError):
        return str(e)[:1000]
    return f"Внутренняя ошибка: {type(e).__name__}"


def enqueue(
    db: Session,
    kind: str,
    payload: dict,
    *,
    project_id: str | None = None,
    title: str = "",
    created_by: str = "",
    dedupe: bool = False,
) -> Job | None:
    """Записывает задачу в текущую транзакцию. dedupe — не ставить, если такая же уже ждёт или идёт."""
    if dedupe:
        for j in db.scalars(select(Job).where(Job.kind == kind, Job.status.in_(["queued", "running"]))):
            if j.payload == payload:
                return None
    job = Job(kind=kind, payload=payload, project_id=project_id, title=title, created_by=created_by)
    db.add(job)
    db.flush()
    return job


runner = JobRunner()
