from sqlalchemy import select

from app import bootstrap
from app.config import get_settings
from app.models import AuditLog, MaintenanceWindow, Project, ScannerSource, SourceLink, User


def test_first_admin_created_once(db, monkeypatch):
    monkeypatch.setenv("VM_ADMIN_PASSWORD", "first-admin-password")
    get_settings.cache_clear()
    try:
        bootstrap.ensure_admin(db)
        bootstrap.ensure_admin(db)
    finally:
        get_settings.cache_clear()
    admins = db.scalars(select(User)).all()
    assert [(u.username, u.roles) for u in admins] == [("admin", ["admin"])]
    assert db.scalar(select(AuditLog).where(AuditLog.action == "user.bootstrap_admin"))


def test_no_admin_without_password(db):
    bootstrap.ensure_admin(db)
    assert db.scalars(select(User)).all() == []


def test_demo_seed_idempotent(db, monkeypatch):
    monkeypatch.setenv("VM_DEMO", "1")
    monkeypatch.setenv("VM_DEMO_PASSWORD", "demo-password-1")
    get_settings.cache_clear()
    try:
        bootstrap.ensure_demo(db)
        bootstrap.ensure_demo(db)
    finally:
        get_settings.cache_clear()
    assert len(db.scalars(select(Project)).all()) == 1
    assert [s.base_url for s in db.scalars(select(ScannerSource))] == ["mock://demo"]
    assert [lk.engagement_id for lk in db.scalars(select(SourceLink))] == [7]
    assert {u.username for u in db.scalars(select(User))} == {"manager", "ciso", "engineer", "engineer2", "viewer"}
    windows = db.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.id)).all()
    assert [(w.name, w.kind) for w in windows] == [("Ночное окно", "recurring"), ("Новогодняя заморозка", "blackout")]


def test_demo_ssh_credentials_and_keys(db, monkeypatch):
    from app.models import HostKey, SshCredential
    from app.services import credentials

    monkeypatch.setenv("VM_DEMO", "1")
    monkeypatch.setenv("VM_DEMO_PASSWORD", "demo-password-1")
    get_settings.cache_clear()
    try:
        pr = bootstrap.ensure_demo(db)
    finally:
        get_settings.cache_clear()
    creds = db.scalars(select(SshCredential).order_by(SshCredential.id)).all()
    assert [(c.name, c.auth) for c in creds] == [("Linux-серверы (deploy)", "password"), ("Базы данных (ключ)", "key")]
    assert credentials.login_for(creds[1]).private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    keys = {k.host: k.status for k in db.scalars(select(HostKey))}
    assert keys["10.20.1.13"] == "mismatch" and keys["10.20.1.11"] == "pinned"
    assert credentials.resolve(creds, "10.20.3.31", {"Базы данных"}).credential is creds[1]
    assert credentials.resolve(creds, "10.20.3.32", set()).credential is creds[0]
    assert credentials.resolve(creds, "10.20.2.21", set()) is None
    assert pr is not None
    # login_for закэшировал настройки с VM_DEMO=1 — сбросить, чтобы демо не протекло в другие тесты.
    get_settings.cache_clear()
