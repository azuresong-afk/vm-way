import base64
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("VM_SECRET_KEY", "test-secret-key-0123456789")
os.environ.setdefault("VM_ENCRYPTION_KEY", base64.b64encode(b"k" * 32).decode())
os.environ.setdefault("VM_DATABASE_URL", "sqlite:///:memory:")
os.environ["VM_ADMIN_PASSWORD"] = ""
os.environ["VM_DEMO"] = "0"
os.environ["VM_JOBS_INLINE"] = "1"
os.environ["VM_POLL_ENABLED"] = "0"
os.environ["VM_VERIFY_POLL_SECONDS"] = "0"
os.environ["VM_JOBS_RETRY_SECONDS"] = "0"
os.environ["VM_JOBS_TICK_SECONDS"] = "0.05"
os.environ["VM_ALLOW_MOCK_SOURCES"] = "1"
os.environ["VM_ROLLOUT_RECONNECT_SECONDS"] = "0.05"
os.environ["VM_ROLLOUT_REBOOT_TIMEOUT_SECONDS"] = "3"

from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbmod  # noqa: E402
from app.audit_guard import create_audit_guard  # noqa: E402
from app.db import Base  # noqa: E402
from app.integrations.scanner import MockScanner  # noqa: E402
from app.models import User  # noqa: E402
from app.schema import head_revision  # noqa: E402
from app.security import hash_password  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture()
def db_url(tmp_path):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    dbmod.configure(url)
    Base.metadata.create_all(dbmod.engine)
    with dbmod.engine.begin() as conn:
        create_audit_guard(conn)
        # Схема создана по моделям — помечаем её последней миграцией, как после alembic upgrade.
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alembic_version VALUES (:v)"), {"v": head_revision()})
    MockScanner.reset()
    yield url
    dbmod.engine.dispose()


@pytest.fixture()
def db(db_url):
    s = dbmod.SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def users(db):
    out = {}
    for name, roles, extra in [
        ("admin", ["admin"], []),
        ("manager", ["manager"], []),
        ("engineer", ["engineer"], ["remediate_execute"]),
        ("viewer", ["viewer"], []),
    ]:
        u = User(
            username=name,
            display_name=name.title(),
            roles=roles,
            extra_perms=extra,
            password_hash=hash_password(PASSWORD),
        )
        db.add(u)
        out[name] = u
    db.commit()
    return out


@pytest.fixture()
def client(db_url):
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def login(client: TestClient, username: str) -> dict:
    r = client.post("/auth/token", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def as_(client, users):
    cache: dict[str, dict] = {}

    def _h(name: str) -> dict:
        if name not in cache:
            cache[name] = login(client, name)
        return cache[name]

    return _h
