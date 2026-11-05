"""Тест-страж цепочки миграций: номера подряд, одна голова, схема совпадает с моделями."""

import re
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app.db import Base

ROOT = Path(__file__).resolve().parents[1]


def _cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_chain_is_continuous():
    script = ScriptDirectory.from_config(_cfg("sqlite://"))
    revs = list(script.walk_revisions())
    assert len(script.get_heads()) == 1, "у цепочки миграций должна быть одна голова"
    ids = sorted(r.revision for r in revs)
    assert ids == [f"{i:04d}" for i in range(1, len(ids) + 1)], ids
    for r in revs:
        expected = None if r.revision == "0001" else f"{int(r.revision) - 1:04d}"
        assert r.down_revision == expected, f"{r.revision} → {r.down_revision}"
        files = list((ROOT / "alembic" / "versions").glob(f"{r.revision}_*.py"))
        assert files and re.match(r"^\d{4}_[a-z0-9_]+\.py$", files[0].name)


def test_upgrade_matches_models_and_downgrade(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        assert diff == [], diff
        triggers = conn.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")).scalars().all()
        assert "audit_log_no_update" in triggers
    command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}


def test_postgres_upgrade_and_audit_trigger():
    """Прогон миграций на настоящем PostgreSQL (в CI задаётся VM_TEST_PG_URL)."""
    import os

    import pytest

    url = os.environ.get("VM_TEST_PG_URL")
    if not url:
        pytest.skip("VM_TEST_PG_URL не задан")
    cfg = _cfg(url)
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log(at, user_sub, username, product, action, object_type, object_id, result, ip) "
                "VALUES (now(), '', 'x', 'vm', 't', '', '', 'ok', '')"
            )
        )
    with pytest.raises(Exception, match="append-only"):  # noqa: B017
        with engine.begin() as conn:
            conn.execute(text("UPDATE audit_log SET action = 'x'"))
    command.downgrade(cfg, "base")


def _row(conn, table: str, **values) -> int:
    """Вставка с заполнением обязательных колонок пустыми значениями по типу."""
    from sqlalchemy import MetaData

    t = MetaData()
    t.reflect(conn, only=[table])
    tbl = t.tables[table]
    data = {}
    for c in tbl.columns:
        if c.name in values or c.nullable or c.primary_key:
            continue
        try:
            py = c.type.python_type
        except NotImplementedError:
            py = str
        data[c.name] = {str: "", int: 0, bool: False, float: 0.0, dict: {}, list: []}.get(py, None)
        if data[c.name] is None:
            from datetime import UTC, datetime

            data[c.name] = datetime.now(UTC)
    data.update(values)
    return conn.execute(tbl.insert().values(**data)).inserted_primary_key[0]


def test_legacy_exceptions_migrated(tmp_path):
    """0006: заявки этапа 1 в «Принят риск» / «Ложное срабатывание» получают действующее исключение."""
    from datetime import date, timedelta

    url = f"sqlite:///{tmp_path / 'legacy.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "0005")
    engine = create_engine(url)
    with engine.begin() as conn:
        uid = _row(conn, "users", username="boss", display_name="Петрова", roles=["manager"])
        _row(conn, "projects", id="p1", name="Порт")
        risk = _row(conn, "tickets", project_id="p1", title="Обновить openssl", status="risk_accepted")
        fp = _row(conn, "tickets", project_id="p1", title="Ядро", status="false_positive")
        _row(conn, "ticket_hosts", ticket_id=risk, host="10.0.0.5")
        _row(
            conn,
            "ticket_history",
            ticket_id=risk,
            actor_id=uid,
            action="status",
            from_value="in_progress",
            to_value="risk_accepted",
            details={"reason": "Сервер выводится"},
        )
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT ticket_id, kind, status, reason, review_on, approver_id, prev_status, hosts "
                "FROM ticket_exceptions ORDER BY ticket_id"
            )
        ).all()
    assert [(r.ticket_id, r.kind, r.status) for r in rows] == [
        (risk, "risk_accepted", "active"),
        (fp, "false_positive", "active"),
    ]
    assert rows[0].reason == "Сервер выводится" and rows[0].approver_id == uid and rows[0].prev_status == "in_progress"
    assert str(rows[0].review_on) == str(date.today() + timedelta(days=90)) and "10.0.0.5" in rows[0].hosts
    assert rows[1].review_on is None and "не сохранилась" in rows[1].reason
