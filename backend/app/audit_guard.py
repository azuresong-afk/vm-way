"""Триггер, запрещающий UPDATE/DELETE в журнале аудита (append-only)."""

from sqlalchemy import text
from sqlalchemy.engine import Connection

PG_FUNC = """
CREATE OR REPLACE FUNCTION vm_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
"""
PG_TRIGGER = """
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION vm_audit_append_only();
"""
SQLITE_TRIGGERS = [
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
]


def create_audit_guard(conn: Connection) -> None:
    if conn.dialect.name == "postgresql":
        conn.execute(text(PG_FUNC))
        conn.execute(text(PG_TRIGGER))
    elif conn.dialect.name == "sqlite":
        for stmt in SQLITE_TRIGGERS:
            conn.execute(text(stmt))


def drop_audit_guard(conn: Connection) -> None:
    if conn.dialect.name == "postgresql":
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log"))
        conn.execute(text("DROP FUNCTION IF EXISTS vm_audit_append_only()"))
    elif conn.dialect.name == "sqlite":
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_update"))
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_delete"))
