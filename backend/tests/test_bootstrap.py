from sqlalchemy import select

from app import bootstrap
from app.config import get_settings
from app.models import AuditLog, Project, ScannerSource, SourceLink, User


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
    assert {u.username for u in db.scalars(select(User))} == {"manager", "engineer", "engineer2", "viewer"}
