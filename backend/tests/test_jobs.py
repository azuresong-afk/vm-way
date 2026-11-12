"""Фоновые задачи: ожидание без занятого потока, повторы временных ошибок, очистка jobs и outbox."""

import time
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import jobs
from app.config import get_settings
from app.db import as_utc, utcnow
from app.integrations.scanner import MockScanner, ScannerError
from app.models import Comment, Job, Outbox, Ticket, Verification
from app.services import importer, verification
from app.services.workflow import Actor

TITLES = [
    "Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3",
    "Обновить libssl3 на Debian 12 до 3.0.14-1~deb12u2",
    "Обновить openssh на РЕД ОС 7.3 до 8.8p1-12.el7",
    "Обновить libexpat1 на Debian 12 до 2.5.0-1+deb12u1",
]


@pytest.fixture()
def project(client, as_):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    link = client.post(
        f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7}
    ).json()
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    return {"id": pid, "link_id": link["id"]}


@pytest.fixture()
def settings(monkeypatch):
    """Настройки с возвратом значений после теста."""
    s = get_settings()

    def _set(**values):
        for k, v in values.items():
            monkeypatch.setattr(s, k, v)

    return _set


@pytest.fixture()
def kind():
    """Регистрация временных обработчиков задач."""
    added = []

    def _add(name, fn, **kw):
        jobs.handler(name, **kw)(fn)
        added.append(name)
        return name

    yield _add
    for name in added:
        jobs._handlers.pop(name, None)


@pytest.fixture()
def inline(db_url):
    """Исполнитель без пула: паузы не выдерживаются, а записываются."""
    r = jobs.JobRunner(inline=True)
    r.delays = []
    r._sleep = r.delays.append
    return r


def _wait(db, cond, seconds=10.0):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        db.expire_all()
        if cond():
            return True
        time.sleep(0.05)
    return False


def _job(db, kind, **payload) -> Job:
    job = jobs.enqueue(db, kind, payload)
    db.commit()
    return job


def _reload(db, job) -> Job:
    db.expire_all()
    return db.get(Job, job.id)


class Flaky:
    """Клиент «Сканера», у которого первые `fails` запросов состояния прогона не проходят."""

    def __init__(self, inner, fails: int, error: ScannerError):
        self._inner, self.fails, self.error, self.calls = inner, fails, error, 0

    def run(self, run_id):
        self.calls += 1
        if self.calls <= self.fails:
            raise self.error
        return self._inner.run(run_id)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _flaky(monkeypatch, fails, error=None):
    error = error or ScannerError("«Сканер» недоступен: ConnectError", transient=True)
    real = importer.client_for
    box = {}

    def client_for(source):
        if "c" not in box:
            box["c"] = Flaky(real(source), fails, error)
        return box["c"]

    monkeypatch.setattr(importer, "client_for", client_for)
    return box


# ---------- ожидание без занятого потока ----------


def test_import_runs_while_four_verifications_wait(db, users, project, settings):
    """Четыре проверки ждут прогон «Сканера» при пуле из четырёх потоков — импорт всё равно идёт."""
    settings(verify_poll_seconds=3600.0)
    mock = MockScanner.shared("demo")
    mock.running_polls = 10**6
    actor = Actor(users["engineer"], {"verify", "ticket_work"})
    waiting = []
    for title in TITLES:
        t = db.scalars(select(Ticket).where(Ticket.title == title)).one()
        [v] = verification.request(db, t, actor)
        waiting.append((v.id, v.result["job_id"]))
    db.commit()
    r = jobs.JobRunner(workers=4)
    r.start(poll=False)
    try:

        def parked():
            rows = [db.get(Job, job_id) for _, job_id in waiting]
            return all(j.status == "queued" and j.run_after is not None for j in rows)

        assert _wait(db, parked), [db.get(Job, j).status for _, j in waiting]
        for vid, _ in waiting:
            v = db.get(Verification, vid)
            assert v.status == "running" and v.scanner_run_id is not None
        # Потоки свободны: импорт ставится и выполняется, пока все четыре проверки ждут.
        imp = jobs.enqueue(db, "import_pending", {"link_ids": [project["link_id"]]}, project_id=project["id"])
        db.commit()
        r.submit(imp.id)
        assert _wait(db, lambda: db.get(Job, imp.id).status == "done"), db.get(Job, imp.id).error
        assert all(db.get(Job, job_id).status == "queued" for _, job_id in waiting)
        # Отложенная задача не запускается раньше срока, даже если её отдать исполнителю явно.
        first = waiting[0][1]
        r.submit(first)
        time.sleep(0.3)
        db.expire_all()
        assert db.get(Job, first).status == "queued"
        # Прогоны завершились, срок подошёл — планировщик сам доводит проверки до конца.
        mock._polls.clear()
        for _, job_id in waiting:
            db.get(Job, job_id).run_after = utcnow()
        db.commit()
        assert _wait(db, lambda: all(db.get(Job, job_id).status == "done" for _, job_id in waiting), 30)
        assert all(db.get(Verification, vid).status == "done" for vid, _ in waiting)
        posts = [x for x in mock.requests if x[0] == "POST" and x[1] == "/engagements/7/runs"]
        assert len(posts) == 4  # ни один прогон не запущен дважды
    finally:
        r.stop()


def test_defer_requeues_and_is_not_an_attempt(db, inline, kind):
    calls = []

    def fn(_db, job):
        calls.append(job.attempts)
        if len(calls) < 5:
            raise jobs.Defer(7)
        return {"calls": len(calls)}

    job = _job(db, kind("t_defer", fn))
    inline.run(job.id)
    job = _reload(db, job)
    assert job.status == "done" and job.result == {"calls": 5}
    assert calls == [1, 1, 1, 1, 1] and job.attempts == 1  # ожидание не тратит попытки
    assert inline.delays == [7, 7, 7, 7] and job.run_after is None


def test_long_jobs_have_their_own_pool(db, db_url, kind):
    """Долгие задачи (раскатки) не занимают потоки коротких."""
    import threading

    assert jobs._handlers["rollout"].pool == "long" and jobs._handlers["rollout_dry_run"].pool == "long"
    assert jobs._handlers["verify"].pool == "main" and jobs._handlers["import_run"].pool == "main"
    release = threading.Event()
    kind("t_long", lambda _db, _job: {"released": release.wait(10)}, pool="long")
    kind("t_short", lambda _db, _job: {"ok": True})
    r = jobs.JobRunner(workers=1, long_workers=1)
    r.start(poll=False)
    try:
        long_job = _job(db, "t_long")
        r.submit(long_job.id)
        assert _wait(db, lambda: db.get(Job, long_job.id).status == "running")
        short = _job(db, "t_short")
        r.submit(short.id)
        assert _wait(db, lambda: db.get(Job, short.id).status == "done")
        assert db.get(Job, long_job.id).status == "running"
        release.set()
        assert _wait(db, lambda: db.get(Job, long_job.id).status == "done")
    finally:
        release.set()
        r.stop()


def test_scheduler_picks_up_queued_jobs(db, db_url, kind):
    """Задачу, которую никто не отдал исполнителю (сбой между записью и запуском), находит планировщик."""
    kind("t_plain", lambda _db, _job: {"ok": True})
    r = jobs.JobRunner(workers=1)
    r.start(poll=False)
    try:
        job = _job(db, "t_plain")
        assert _wait(db, lambda: db.get(Job, job.id).status == "done")
    finally:
        r.stop()


# ---------- повторы ----------


def test_transient_error_is_retried(db, inline, kind, settings):
    settings(jobs_retry_seconds=30.0)
    calls = []

    def fn(_db, _job):
        calls.append(1)
        if len(calls) < jobs.MAX_ATTEMPTS:
            raise ScannerError("«Сканер» ответил HTTP 503 на GET /runs/1", 503)
        return {"ok": True}

    job = _job(db, kind("t_retry", fn))
    assert inline._run_once(job.id) == 30.0
    job = _reload(db, job)
    assert job.status == "queued" and job.attempts == 1 and "будет повтор" in job.error and "503" in job.error
    assert as_utc(job.run_after) > utcnow() + timedelta(seconds=20) and job.finished_at is None
    inline.run(job.id)
    job = _reload(db, job)
    assert job.status == "done" and job.attempts == jobs.MAX_ATTEMPTS and job.error == ""
    assert inline.delays == [120.0]  # паузы растут: 30 с, затем 2 мин


def test_gives_up_after_max_attempts(db, inline, kind):
    calls, gave_up = [], []

    def fn(_db, _job):
        calls.append(1)
        raise ScannerError("«Сканер» недоступен: ConnectError", transient=True)

    job = _job(db, kind("t_down", fn, on_failed=lambda _db, j, e: gave_up.append((j.id, str(e)))))
    inline.run(job.id)
    job = _reload(db, job)
    assert len(calls) == jobs.MAX_ATTEMPTS == 3 and job.attempts == 3
    assert job.status == "failed" and job.error == "«Сканер» недоступен: ConnectError" and job.finished_at
    assert gave_up == [(job.id, "«Сканер» недоступен: ConnectError")]  # один раз, в самом конце


@pytest.mark.parametrize(
    "error",
    [ScannerError("«Сканер» ответил HTTP 404", 404), ScannerError("Адрес неверен"), ValueError("плохо"), KeyError()],
)
def test_permanent_error_is_final_at_once(db, inline, kind, error):
    calls = []

    def fn(_db, _job):
        calls.append(1)
        raise error

    job = _job(db, kind("t_bad", fn))
    inline.run(job.id)
    job = _reload(db, job)
    assert len(calls) == 1 and job.status == "failed" and job.attempts == 1 and inline.delays == []


def test_no_retry_handlers_run_once(db, inline, kind):
    """Раскатки не повторяются сами: повторный запуск команд на хостах — решение человека."""
    assert jobs._handlers["rollout"].max_attempts == 1 and jobs._handlers["rollout_dry_run"].max_attempts == 1
    calls = []

    def fn(_db, _job):
        calls.append(1)
        raise ScannerError("«Сканер» недоступен", transient=True)

    job = _job(db, kind("t_once", fn, retry=False))
    inline.run(job.id)
    assert len(calls) == 1 and _reload(db, job).status == "failed"


def test_transient_classification():
    assert ScannerError("x", 500).transient and ScannerError("x", 429).transient
    assert ScannerError("x", transient=True).transient
    assert not ScannerError("x", 401).transient and not ScannerError("x").transient
    assert jobs.is_transient(ConnectionError()) and not jobs.is_transient(RuntimeError())


def _verify_job(db, users, title=TITLES[1]):
    t = db.scalars(select(Ticket).where(Ticket.title == title)).one()
    [v] = verification.request(db, t, Actor(users["engineer"], {"verify", "ticket_work"}))
    db.commit()
    return v, db.get(Job, v.result["job_id"])


def test_verification_survives_scanner_blip(db, users, project, monkeypatch):
    """«Сканер» дважды не ответил на вопрос о прогоне — проверка дожидается и завершается."""
    box = _flaky(monkeypatch, fails=2)
    v, job = _verify_job(db, users)
    jobs.runner.run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "done" and box["c"].calls >= 3
    v = db.get(Verification, v.id)
    assert v.status == "done" and v.result["outcome"] == "verified"


def test_verification_fails_cleanly_when_scanner_is_down(db, users, project, monkeypatch, client, as_):
    """«Сканер» не отвечает совсем — после MAX_ATTEMPTS попыток проверка «не выполнена», а не висит."""
    box = _flaky(monkeypatch, fails=10**6)
    v, job = _verify_job(db, users)
    jobs.runner.run(job.id)
    db.expire_all()
    job = db.get(Job, job.id)
    assert job.status == "failed" and job.attempts == jobs.MAX_ATTEMPTS and box["c"].calls == jobs.MAX_ATTEMPTS
    v = db.get(Verification, v.id)
    assert v.status == "failed" and "недоступен" in v.error and v.finished_at is not None
    notes = db.scalars(select(Comment).where(Comment.ticket_id == v.ticket_id, Comment.kind == "system")).all()
    assert sum("Повторная проверка не выполнена" in c.body for c in notes) == 1
    # Заявку можно проверить снова.
    r = client.post(f"/tickets/{v.ticket_id}/verify", headers=as_("engineer"), json={})
    assert r.status_code != 409


def test_run_after_in_api(client, as_, db, project, kind, inline, settings):
    settings(jobs_retry_seconds=30.0)

    def fn(_db, _job):
        raise ScannerError("«Сканер» недоступен", transient=True)

    job = jobs.enqueue(db, kind("t_api", fn), {}, project_id=project["id"])
    db.commit()
    inline._run_once(job.id)
    out = client.get(f"/jobs/{job.id}", headers=as_("viewer")).json()
    assert out["status"] == "queued" and out["run_after"] and out["attempts"] == 1


# ---------- очистка ----------


def _old_job(db, status, days, **kw) -> int:
    at = utcnow() - timedelta(days=days)
    job = Job(kind="import_run", status=status, payload={}, created_at=at, **kw)
    if status in ("done", "failed"):
        job.finished_at = at
    db.add(job)
    db.flush()
    return job.id


def _event(db, days, delivered_days=None) -> str:
    ev = Outbox(type="vm.test", data={}, created_at=utcnow() - timedelta(days=days))
    if delivered_days is not None:
        ev.delivered_at = utcnow() - timedelta(days=delivered_days)
    db.add(ev)
    db.flush()
    return ev.id


def test_prune_jobs_and_outbox(db):
    s = get_settings()
    assert (s.jobs_retention_days, s.outbox_retention_days, s.outbox_undelivered_retention_days) == (30, 30, 90)
    old_done, old_failed = _old_job(db, "done", 31), _old_job(db, "failed", 45)
    keep = [
        _old_job(db, "done", 29),
        _old_job(db, "failed", 1),
        _old_job(db, "queued", 400),  # незавершённые не трогаем, сколько бы ни ждали
        _old_job(db, "running", 400),
    ]
    gone_events = [_event(db, 60, delivered_days=31), _event(db, 91)]
    keep_events = [_event(db, 60, delivered_days=29), _event(db, 89), _event(db, 0)]
    db.commit()
    assert jobs.prune(db) == {"jobs": 2, "outbox": 2}
    db.commit()
    db.expire_all()
    assert db.get(Job, old_done) is None and db.get(Job, old_failed) is None
    assert all(db.get(Job, i) is not None for i in keep)
    assert all(db.get(Outbox, i) is None for i in gone_events)
    assert all(db.get(Outbox, i) is not None for i in keep_events)
    assert jobs.prune(db) == {"jobs": 0, "outbox": 0}


def test_prune_can_be_switched_off(db, settings):
    settings(jobs_retention_days=0, outbox_retention_days=0, outbox_undelivered_retention_days=0)
    _old_job(db, "done", 1000)
    _event(db, 1000)
    _event(db, 1000, delivered_days=999)
    db.commit()
    assert jobs.prune(db) == {"jobs": 0, "outbox": 0}
    assert db.scalar(select(func.count()).select_from(Job)) == 1
    assert db.scalar(select(func.count()).select_from(Outbox)) == 2


def test_scheduler_prunes_on_start(db, db_url):
    old = _old_job(db, "done", 365)
    db.commit()
    r = jobs.JobRunner(workers=1)
    r.start(poll=False)
    try:
        assert _wait(db, lambda: db.get(Job, old) is None)
    finally:
        r.stop()
