"""Блокировка импорта на проект: параллельные импорты одного проекта идут по очереди.

Гонки воспроизводятся только на настоящем PostgreSQL (VM_TEST_PG_URL и VM_TEST_ON_PG=1).
"""

import threading

from sqlalchemy import func, select

from app import db as dbmod
from app.models import AssetGroup, AuditLog, ScanRun, SourceLink
from app.services import assets, importer
from tests.conftest import requires_pg
from tests.test_sources_import import _linked

pytestmark = requires_pg


def _together(monkeypatch, module=importer, name: str = "fetch_results") -> None:
    """Сводит два потока в одной точке — на выходе из функции `name` (по умолчанию сразу после
    получения результатов из «Сканера»).

    Без блокировки оба потока проходят барьер одновременно и пишут в базу наперегонки.
    С блокировкой до барьера доходит только один поток: он ждёт секунду и продолжает."""
    barrier = threading.Barrier(2, timeout=1.0)
    original = getattr(module, name)

    def wrapped(*args, **kwargs):
        out = original(*args, **kwargs)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return out

    monkeypatch.setattr(module, name, wrapped)


def _parallel(*works) -> list:
    """Запускает работы в отдельных потоках со своими сессиями; возвращает результаты или ошибки."""
    out: list = [None] * len(works)

    def run(i, work):
        s = dbmod.SessionLocal()
        try:
            out[i] = work(s)
            s.commit()
        except Exception as e:  # noqa: BLE001 — ошибку потока проверяет тест
            s.rollback()
            out[i] = e
        finally:
            s.close()

    threads = [threading.Thread(target=run, args=(i, w)) for i, w in enumerate(works)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "импорт завис"
    return out


def test_parallel_imports_of_one_project_do_not_fail(client, as_, db, monkeypatch):
    """Два разных прогона одного проекта импортируются одновременно — раньше второй падал
    с UniqueViolation uq_asset_group_project_name."""
    _, _, link = _linked(client, as_)
    _together(monkeypatch)

    def work(run_id):
        return lambda s: importer.import_run(s, s.get(SourceLink, link["id"]), run_id)[1]

    assert _parallel(work(100), work(101)) == [True, True]
    assert sorted(db.scalars(select(ScanRun.scanner_run_id))) == [100, 101]
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "run.import")) == 2


def test_parallel_import_pending_keeps_run_order(client, as_, db, monkeypatch):
    """Два параллельных «импортировать всё»: каждый прогон создаётся один раз, от старых к новым,
    как при последовательном импорте."""
    _, _, link = _linked(client, as_)
    _together(monkeypatch)

    def work(s):
        return importer.import_pending(s, s.get(SourceLink, link["id"]))

    first, second = _parallel(work, work)
    assert not isinstance(first, Exception), first
    assert not isinstance(second, Exception), second
    by_id = sorted(db.scalars(select(ScanRun)), key=lambda r: r.id)
    assert [r.scanner_run_id for r in by_id] == [100, 101, 102]
    assert sorted(first + second) == [r.id for r in by_id]


def test_same_run_imported_once(client, as_, db, monkeypatch):
    _, _, link = _linked(client, as_)
    _together(monkeypatch)

    def work(s):
        return importer.import_run(s, s.get(SourceLink, link["id"]), 101)[1]

    assert sorted(_parallel(work, work)) == [False, True]
    assert db.scalar(select(func.count()).select_from(ScanRun)) == 1


def test_asset_sync_waits_for_import(client, as_, db, monkeypatch):
    """Кнопка «Обновить из «Сканера»» во время импорта не создаёт группы активов наперегонки с ним."""
    pid, _, link = _linked(client, as_)
    # Оба потока встречаются перед записью активов: группы уже созданы в сессии, но не зафиксированы.
    _together(monkeypatch, assets, "_group_rows")

    def do_import(s):
        return importer.import_run(s, s.get(SourceLink, link["id"]), 100)[1]

    def do_sync(s):
        return assets.sync_project(s, pid)["errors"]

    assert _parallel(do_import, do_sync) == [True, []]
    names = list(db.scalars(select(AssetGroup.name).where(AssetGroup.project_id == pid)))
    assert names and len(names) == len(set(names))
