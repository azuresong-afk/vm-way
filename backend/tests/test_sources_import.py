"""Задача 1.3: источники, привязки, импорт прогонов по кнопке и опросом, без дублей."""

from sqlalchemy import func, select

from app import jobs
from app.config import get_settings
from app.integrations.scanner import MockScanner
from app.models import AuditLog, Job, RunCoverage, ScannerSource, ScanRun, SourceLink
from app.services import importer


def _source(client, as_, **kw) -> dict:
    body = {"name": "Сканер", "base_url": "mock://demo", "username": "svc-vm", "password": "svc-secret-pw", **kw}
    r = client.post("/sources", headers=as_("admin"), json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _project(client, as_) -> str:
    return client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]


def _linked(client, as_) -> tuple[str, dict, dict]:
    pid = _project(client, as_)
    src = _source(client, as_)
    link = client.post(
        f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7}
    )
    assert link.status_code == 201, link.text
    return pid, src, link.json()


def test_source_secret_is_encrypted_and_hidden(client, as_, db):
    src = _source(client, as_)
    assert src["has_password"] is True and "password" not in src
    row = db.get(ScannerSource, src["id"])
    assert row.secret_enc.startswith("v1:") and "svc-secret-pw" not in row.secret_enc
    for e in db.scalars(select(AuditLog)):
        assert "svc-secret-pw" not in str(e.details)
    # Пустой пароль при правке не стирает сохранённый.
    client.patch(f"/sources/{src['id']}", headers=as_("admin"), json={"name": "Сканер-2", "password": ""})
    db.expire_all()
    assert db.get(ScannerSource, src["id"]).secret_enc == row.secret_enc


def test_source_validation_and_mock_guard(client, as_, monkeypatch):
    r = client.post("/sources", headers=as_("admin"), json={"name": "x", "base_url": "ftp://scanner"})
    assert r.status_code == 422
    monkeypatch.setenv("VM_ALLOW_MOCK_SOURCES", "0")
    get_settings.cache_clear()
    try:
        r = client.post("/sources", headers=as_("admin"), json={"name": "x", "base_url": "mock://demo"})
        assert r.status_code == 422
    finally:
        get_settings.cache_clear()


def test_sources_are_admin_only(client, as_):
    for who in ("manager", "engineer", "viewer"):
        assert client.get("/sources", headers=as_(who)).status_code == 403


def test_test_connection_reports_roles(client, as_):
    src = _source(client, as_)
    r = client.post(f"/sources/{src['id']}/test", headers=as_("admin")).json()
    assert r["ok"] and r["username"] == "svc-vm" and r["warnings"] == []


def test_engagements_and_links(client, as_):
    pid, src, link = _linked(client, as_)
    engs = client.get(f"/sources/{src['id']}/engagements", headers=as_("admin")).json()
    assert engs[0]["id"] == 7 and engs[0]["linked_project_id"] == pid
    assert link["engagement_name"].startswith("АО «Северный порт»")
    dup = client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    assert dup.status_code == 409
    bad = client.post(
        f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 99}
    )
    assert bad.status_code == 422
    assert client.get(f"/projects/{pid}/links", headers=as_("viewer")).json()[0]["engagement_id"] == 7
    # Источник с привязками удалить нельзя.
    assert client.delete(f"/sources/{src['id']}", headers=as_("admin")).status_code == 409


def test_import_pending_oldest_first_and_no_duplicates(client, as_, db):
    pid, _, _ = _linked(client, as_)
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    runs = client.get(f"/projects/{pid}/runs", headers=as_("viewer"))
    assert runs.headers["X-Total-Count"] == "3"
    # Импорт шёл от старых к новым.
    by_id = sorted(db.scalars(select(ScanRun)), key=lambda r: r.id)
    assert [r.scanner_run_id for r in by_id] == [100, 101, 102]
    assert by_id[2].status == "partial" and by_id[2].stats["hosts_unchecked"] == 1
    assert by_id[2].stats["credential_ids"] == [3]
    assert db.scalar(select(func.count()).select_from(RunCoverage)) == 3 * 20 * 3
    # Повторный импорт ничего не создаёт.
    again = client.post(f"/projects/{pid}/import", headers=as_("manager"), json={}).json()
    assert again["status"] == "done" and again["result"]["imported"] == []
    assert db.scalar(select(func.count()).select_from(ScanRun)) == 3
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "run.import")) == 3


def test_import_specific_run_is_idempotent(client, as_, db):
    pid, _, link = _linked(client, as_)
    first = client.post(
        f"/projects/{pid}/import", headers=as_("engineer"), json={"link_id": link["id"], "scanner_run_id": 101}
    ).json()
    second = client.post(
        f"/projects/{pid}/import", headers=as_("engineer"), json={"link_id": link["id"], "scanner_run_id": 101}
    ).json()
    assert first["result"]["created"] is True and second["result"]["created"] is False
    assert first["result"]["run_id"] == second["result"]["run_id"]
    listed = client.get(f"/projects/{pid}/scanner-runs", headers=as_("engineer"), params={"link_id": link["id"]}).json()
    assert {r["id"]: r["imported_run_id"] is not None for r in listed} == {102: False, 101: True, 100: False}


def test_unfinished_run_is_not_imported(client, as_, db):
    pid, _, link = _linked(client, as_)
    mock = MockScanner.shared("demo")
    mock.running_polls = 100
    started = mock.client().start_run(7, {"targets": ["10.20.1.11"], "modules": ["vuln"]})
    job = client.post(
        f"/projects/{pid}/import",
        headers=as_("engineer"),
        json={"link_id": link["id"], "scanner_run_id": started["id"]},
    ).json()
    assert job["status"] == "failed" and "ещё не завершён" in job["error"]
    assert db.scalar(select(func.count()).select_from(ScanRun)) == 0


def test_import_permissions(client, as_):
    pid, _, _ = _linked(client, as_)
    assert client.post(f"/projects/{pid}/import", headers=as_("admin"), json={}).status_code == 403
    assert client.post(f"/projects/{pid}/import", headers=as_("viewer"), json={}).status_code == 403


def test_import_without_link(client, as_):
    pid = _project(client, as_)
    assert client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).status_code == 422


def test_poll_source_imports_and_records_errors(client, as_, db):
    pid, src, _ = _linked(client, as_)
    assert importer.due_sources(db) == [src["id"]]
    job = jobs.enqueue(db, "poll_source", {"source_id": src["id"]})
    db.commit()
    jobs.runner.run(job.id)
    db.expire_all()
    assert db.get(Job, job.id).status == "done"
    assert db.scalar(select(func.count()).select_from(ScanRun)) == 3
    assert importer.due_sources(db) == []  # опрошен только что
    # Привязка к проекту «Сканера», которого нет, — ошибка пишется в источник.
    db.add(SourceLink(source_id=src["id"], project_id=pid, engagement_id=99))
    db.commit()
    job2 = jobs.enqueue(db, "poll_source", {"source_id": src["id"]})
    db.commit()
    jobs.runner.run(job2.id)
    db.expire_all()
    assert db.get(Job, job2.id).status == "failed"
    assert "404" in db.get(ScannerSource, src["id"]).last_error


def test_jobs_recovered_after_restart(client, as_, db):
    pid, _, link = _linked(client, as_)
    job = jobs.enqueue(db, "import_run", {"link_id": link["id"], "scanner_run_id": 100}, project_id=pid)
    job.status = "running"  # процесс упал посреди задачи
    db.commit()
    jobs.runner.recover()
    db.expire_all()
    assert db.get(Job, job.id).status == "done"
    assert client.get(f"/projects/{pid}/jobs", headers=as_("viewer")).json()[0]["status"] == "done"


def test_dedupe_enqueue(db):
    assert jobs.enqueue(db, "poll_source", {"source_id": 1}, dedupe=True) is not None
    assert jobs.enqueue(db, "poll_source", {"source_id": 1}, dedupe=True) is None


def test_threaded_runner(client, as_, db):
    """Настоящий пул потоков: задача выполняется вне запроса."""
    import time

    pid, _, link = _linked(client, as_)
    r = jobs.JobRunner(workers=2)
    r.start(poll=False)
    try:
        job = jobs.enqueue(db, "import_run", {"link_id": link["id"], "scanner_run_id": 102}, project_id=pid)
        db.commit()
        r.submit(job.id)
        for _ in range(100):
            db.expire_all()
            if db.get(Job, job.id).status in ("done", "failed"):
                break
            time.sleep(0.05)
        assert db.get(Job, job.id).status == "done"
    finally:
        r.stop()
