"""Фоновые задачи в процессе API: пулы потоков, состояние — в таблице jobs.

Задача сначала записывается в БД (queued), затем исполняется в пуле. При старте процесса
незавершённые задачи (queued/running) возвращаются в очередь — работа переживает рестарт.

Ожидание без занятого потока. Обработчик, которому нужно ждать внешнюю систему (прогон «Сканера»),
не спит в потоке, а бросает `Defer(секунды)`: задача возвращается в очередь со сроком `run_after`,
поток освобождается, планировщик запустит её снова, когда срок подойдёт. Раскатки работают с хостами
долго и идут в отдельном пуле (`pool="long"`), поэтому не задерживают импорт, опрос и проверки.

Повторы. Временная ошибка (сеть, 5xx «Сканера», сбой соединения с БД) не окончательна: задача
повторяется с растущей паузой, всего не больше `MAX_ATTEMPTS` попыток подряд. Остальные ошибки
окончательны сразу. Обработчик с `retry=False` (раскатки) не повторяется никогда.

Планировщик — один поток: раз в `VM_JOBS_TICK_SECONDS` запускает задачи, у которых подошёл срок,
раз в минуту ставит в очередь опрос источников и закрывает исключения с прошедшей датой пересмотра,
раз в час удаляет старые записи jobs и outbox (сроки хранения — в настройках).
"""

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal, utcnow
from app.models import Job, Outbox

log = logging.getLogger("vm.jobs")

Handler = Callable[[Session, Job], dict | None]
FailureHook = Callable[[Session, Job, Exception], None]
# Попыток подряд на одну задачу: первая и повторы после временных ошибок.
MAX_ATTEMPTS = 3
POOLS = ("main", "long")
POLL_EVERY_SECONDS = 60.0
PRUNE_EVERY_SECONDS = 3600.0
DISPATCH_BATCH = 200


class Defer(Exception):
    """Обработчик просит вызвать его снова через `seconds`: ждём внешнюю систему, поток не держим.

    Всё, что нужно сохранить, обработчик фиксирует сам до исключения. Отложенный вызов — не ошибка:
    счётчик попыток сбрасывается."""

    def __init__(self, seconds: float):
        super().__init__(f"отложено на {seconds} с")
        self.seconds = max(0.0, float(seconds))


@dataclass(frozen=True)
class Spec:
    fn: Handler
    pool: str = "main"
    max_attempts: int = MAX_ATTEMPTS
    on_failed: FailureHook | None = None


_handlers: dict[str, Spec] = {}


def handler(
    kind: str, *, pool: str = "main", retry: bool = True, on_failed: FailureHook | None = None
) -> Callable[[Handler], Handler]:
    """Регистрирует обработчик задач вида `kind`.

    pool — "main" (короткие задачи) или "long" (долгая работа, раскатки); retry=False — не повторять
    даже после временной ошибки; on_failed(db, job, error) вызывается, когда задача провалилась
    окончательно, — чтобы довести до конечного статуса то, чем она занималась."""
    if pool not in POOLS:
        raise ValueError(f"неизвестный пул задач: {pool}")

    def deco(fn: Handler) -> Handler:
        _handlers[kind] = Spec(fn, pool, MAX_ATTEMPTS if retry else 1, on_failed)
        return fn

    return deco


def is_transient(e: Exception) -> bool:
    """Временная ли ошибка: повтор через некоторое время может пройти."""
    from app.integrations.scanner import ScannerError

    if isinstance(e, ScannerError):
        return e.transient
    if isinstance(e, OperationalError | InterfaceError):
        return True
    if isinstance(e, DBAPIError):
        return bool(e.connection_invalidated)
    return isinstance(e, httpx.TransportError | ConnectionError | TimeoutError)


def retry_delay(attempt: int) -> float:
    """Пауза перед повтором после попытки №attempt: 30 с, 2 мин, 8 мин… (база — в настройках)."""
    return get_settings().jobs_retry_seconds * 4 ** max(0, attempt - 1)


class JobRunner:
    def __init__(self, workers: int | None = None, inline: bool = False, long_workers: int | None = None):
        self.inline = inline
        self._workers = workers
        self._long_workers = long_workers
        self._pools: dict[str, ThreadPoolExecutor] = {}
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None
        self._lock = threading.Lock()
        # Задачи, уже отданные в пул и ещё не отработавшие: планировщик не отдаёт их второй раз.
        self._pending: set[int] = set()
        self._sleep: Callable[[float], None] = time.sleep

    # --- жизненный цикл ---
    def start(self, poll: bool = True) -> None:
        s = get_settings()
        self._stop.clear()
        if not self.inline:
            sizes = {"main": self._workers or s.jobs_workers, "long": self._long_workers or s.jobs_long_workers}
            self._pools = {
                name: ThreadPoolExecutor(max_workers=max(1, sizes[name]), thread_name_prefix=f"vm-job-{name}")
                for name in POOLS
            }
        self.recover()
        if not self.inline:
            self._ticker = threading.Thread(target=self._loop, args=(poll,), name="vm-jobs-ticker", daemon=True)
            self._ticker.start()

    def stop(self) -> None:
        self._stop.set()
        if self._ticker is not None and self._ticker is not threading.current_thread():
            self._ticker.join(timeout=5)
        self._ticker = None
        pools, self._pools = self._pools, {}
        for pool in pools.values():
            pool.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            self._pending.clear()

    def recover(self) -> None:
        """Незавершённые задачи после рестарта — снова в очередь."""
        with SessionLocal() as db:
            ids = []
            for job in db.scalars(select(Job).where(Job.status.in_(["queued", "running"]))):
                if job.status == "running":
                    job.status = "queued"
                    job.run_after = None
                    job.error = "Служба перезапускалась — задача поставлена в очередь заново"
                ids.append((job.id, job.kind))
            db.commit()
        for job_id, kind in ids:
            self.submit(job_id, kind=kind)

    # --- постановка и исполнение ---
    def submit(self, job_id: int, *, kind: str | None = None) -> None:
        """Отдаёт задачу на исполнение. Задача со сроком `run_after` в будущем подождёт планировщика."""
        if self.inline or not self._pools:
            self.run(job_id)
            return
        with self._lock:
            if job_id in self._pending:
                return
            self._pending.add(job_id)
        try:
            if kind is None:
                with SessionLocal() as db:
                    kind = db.scalar(select(Job.kind).where(Job.id == job_id))
            spec = _handlers.get(kind or "")
            self._pools[spec.pool if spec else "main"].submit(self._run_pooled, job_id)
        except Exception:
            with self._lock:
                self._pending.discard(job_id)
            if not self._stop.is_set():
                raise

    def _run_pooled(self, job_id: int) -> None:
        try:
            self._run_once(job_id)
        except Exception:  # noqa: BLE001 — поток пула не должен терять исключение молча
            log.exception("Сбой исполнения задачи %s", job_id)
        finally:
            with self._lock:
                self._pending.discard(job_id)

    def run(self, job_id: int) -> None:
        """Исполняет задачу в текущем потоке до конечного статуса (режим без пула, тесты):
        отложенные вызовы и повторы идут тут же, после паузы."""
        while True:
            delay = self._run_once(job_id, force=True)
            if delay is None:
                return
            self._sleep(delay)

    def _run_once(self, job_id: int, *, force: bool = False) -> float | None:
        """Один вызов обработчика. Возвращает паузу в секундах, если задача вернулась в очередь."""
        with SessionLocal() as db:
            now = utcnow()
            due = [Job.id == job_id, Job.status == "queued"]
            if not force:
                due.append(or_(Job.run_after.is_(None), Job.run_after <= now))
            # Захват одной командой: задачу не возьмут два потока (и два процесса) сразу.
            claimed = db.execute(
                update(Job)
                .where(*due)
                .values(
                    status="running",
                    started_at=func.coalesce(Job.started_at, now),
                    attempts=Job.attempts + 1,
                    run_after=None,
                )
                .execution_options(synchronize_session=False)
            ).rowcount
            db.commit()
            if not claimed:
                return None
            job = db.get(Job, job_id)
            db.refresh(job)
            spec = _handlers.get(job.kind)
            delay: float | None = None
            try:
                if spec is None:
                    raise RuntimeError(f"нет обработчика задачи {job.kind}")
                result = spec.fn(db, job)
                db.refresh(job)
                job.status, job.result, job.error = "done", result or {}, ""
                job.finished_at = utcnow()
            except Defer as d:
                db.rollback()
                job = db.get(Job, job_id)
                delay = d.seconds
                job.status, job.error, job.attempts = "queued", "", 0
                job.run_after = utcnow() + timedelta(seconds=delay)
            except Exception as e:  # noqa: BLE001 — любая ошибка задачи пишется в её запись
                db.rollback()
                job = db.get(Job, job_id)
                limit = spec.max_attempts if spec else 1
                if is_transient(e) and job.attempts < limit:
                    delay = retry_delay(job.attempts)
                    log.warning(
                        "Задача %s (%s): попытка %s из %s не удалась (%s), повтор через %.0f с",
                        job_id,
                        job.kind,
                        job.attempts,
                        limit,
                        e,
                        delay,
                    )
                    job.status = "queued"
                    job.run_after = utcnow() + timedelta(seconds=delay)
                    job.error = f"Попытка {job.attempts} из {limit} не удалась, будет повтор: {safe_error(e)}"[:1000]
                else:
                    log.warning("Задача %s (%s) завершилась ошибкой: %s", job_id, job.kind, e)
                    if spec is not None and spec.on_failed is not None:
                        try:
                            spec.on_failed(db, job, e)
                            db.commit()
                        except Exception:  # noqa: BLE001
                            db.rollback()
                            log.exception("Сбой завершения проваленной задачи %s (%s)", job_id, job.kind)
                        job = db.get(Job, job_id)
                    job.status = "failed"
                    job.error = safe_error(e)
                    job.finished_at = utcnow()
            db.commit()
            return delay

    # --- планировщик ---
    def dispatch_due(self) -> int:
        """Отдаёт в пулы задачи в очереди, у которых подошёл срок. Возвращает, сколько отдано."""
        with self._lock:
            pending = set(self._pending)
        with SessionLocal() as db:
            now = utcnow()
            rows = db.execute(
                select(Job.id, Job.kind)
                .where(Job.status == "queued", or_(Job.run_after.is_(None), Job.run_after <= now))
                .order_by(Job.id)
                .limit(DISPATCH_BATCH + len(pending))
            ).all()
        n = 0
        for job_id, kind in rows:
            if job_id not in pending:
                self.submit(job_id, kind=kind)
                n += 1
        return n

    def _loop(self, poll: bool) -> None:
        tick = max(0.05, get_settings().jobs_tick_seconds)
        next_poll = next_prune = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                self.dispatch_due()
            except Exception:  # noqa: BLE001
                log.exception("Сбой планировщика задач")
            if poll and now >= next_poll:
                next_poll = now + POLL_EVERY_SECONDS
                self._poll_sources()
                self._expire_exceptions()
            if now >= next_prune:
                next_prune = now + PRUNE_EVERY_SECONDS
                try:
                    with SessionLocal() as db:
                        removed = prune(db)
                        db.commit()
                    if any(removed.values()):
                        log.info("Очистка: удалено задач %(jobs)s, событий outbox %(outbox)s", removed)
                except Exception:  # noqa: BLE001
                    log.exception("Сбой очистки jobs и outbox")
            if self._stop.wait(tick):
                return

    def _poll_sources(self) -> None:
        from app.services.importer import due_sources

        try:
            with SessionLocal() as db:
                for source_id in due_sources(db):
                    job = enqueue(db, "poll_source", {"source_id": source_id}, title="Опрос «Сканера»", dedupe=True)
                    db.commit()
                    if job:
                        self.submit(job.id, kind=job.kind)
        except Exception:  # noqa: BLE001
            log.exception("Сбой опроса источников")

    def _expire_exceptions(self) -> None:
        """Исключения, у которых прошла дата пересмотра, истекают (задача 2.5)."""
        from app.services.exceptions import expire_due

        try:
            with SessionLocal() as db:
                expired = expire_due(db)
                db.commit()
                for job in expired:
                    self.submit(job.id, kind=job.kind)
        except Exception:  # noqa: BLE001
            log.exception("Сбой проверки дат пересмотра исключений")


def safe_error(e: Exception) -> str:
    """Текст ошибки, который можно показать пользователю."""
    from app.integrations.scanner import ScannerError

    if isinstance(e, ScannerError | ValueError | LookupError):
        return str(e)[:1000]
    return f"Внутренняя ошибка: {type(e).__name__}"


def prune(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Удаляет записи старше срока хранения: завершённые задачи и события outbox.

    Задачи — только в конечном статусе (done/failed), по времени завершения. События outbox:
    доставленные — по времени доставки, недоставленные — по времени создания (у них свой, более
    длинный срок: пока получателя нет, иначе таблица росла бы без конца; те же события остаются в
    журнале аудита, который не чистится). Срок 0 отключает очистку. Коммит — у вызывающего кода."""
    s = get_settings()
    now = now or utcnow()
    out = {"jobs": 0, "outbox": 0}
    if s.jobs_retention_days > 0:
        cutoff = now - timedelta(days=s.jobs_retention_days)
        out["jobs"] = db.execute(
            delete(Job)
            .where(Job.status.in_(["done", "failed"]), Job.finished_at < cutoff)
            .execution_options(synchronize_session=False)
        ).rowcount
    if s.outbox_retention_days > 0:
        cutoff = now - timedelta(days=s.outbox_retention_days)
        out["outbox"] += db.execute(
            delete(Outbox)
            .where(Outbox.delivered_at.is_not(None), Outbox.delivered_at < cutoff)
            .execution_options(synchronize_session=False)
        ).rowcount
    if s.outbox_undelivered_retention_days > 0:
        cutoff = now - timedelta(days=s.outbox_undelivered_retention_days)
        out["outbox"] += db.execute(
            delete(Outbox)
            .where(Outbox.delivered_at.is_(None), Outbox.created_at < cutoff)
            .execution_options(synchronize_session=False)
        ).rowcount
    return out


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
