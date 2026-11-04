import base64

from sqlalchemy import text

from app.config import Settings
from app.preflight import check

GOOD = {
    "secret_key": "s" * 48,
    "encryption_key": base64.b64encode(b"k" * 32).decode(),
    "admin_password": "admin-password-1",
    "database_url": "postgresql+psycopg://vm:vm@db:5432/vm",
}


def settings(**over) -> Settings:
    return Settings(_env_file=None, **{**GOOD, **over})


def test_good_settings_pass():
    errors, warnings = check(settings())
    assert errors == [] and warnings == []


def test_empty_and_placeholder_secrets_stop_start():
    errors, _ = check(settings(secret_key="", encryption_key="CHANGE_ME"))
    assert any("VM_SECRET_KEY" in e for e in errors)
    assert any("VM_ENCRYPTION_KEY" in e for e in errors)


def test_weak_values_stop_start():
    errors, _ = check(
        settings(
            secret_key="short",
            encryption_key=base64.b64encode(b"k" * 16).decode(),
            admin_password="CHANGE_ME_please",
        )
    )
    assert len(errors) == 3


def test_demo_requires_password_and_warns():
    errors, warnings = check(settings(demo=True, demo_password=""))
    assert any("VM_DEMO_PASSWORD" in e for e in errors)
    errors, warnings = check(settings(demo=True, demo_password="demo-password-1"))
    assert errors == [] and any("демо" in w for w in warnings)


def test_platform_mode_not_yet_available():
    errors, _ = check(settings(auth_mode="platform"))
    assert any("этапе 3" in e for e in errors)


def test_ready_requires_latest_migration(client, db):
    assert client.get("/health/ready").status_code == 200
    db.execute(text("UPDATE alembic_version SET version_num = 'old'"))
    db.commit()
    r = client.get("/health/ready")
    assert r.status_code == 503 and "миграции" in r.json()["detail"]
    db.execute(text("DROP TABLE alembic_version"))
    db.commit()
    assert client.get("/health/ready").status_code == 503
