"""Исключения (задача 2.5): принятие риска и ложные срабатывания с утверждающим и датой пересмотра;
флажок источника «отмечать ложные срабатывания в «Сканере»».

Заявки, которые на этапе 1 руководитель перевёл в «Принят риск» или «Ложное срабатывание», получают
действующее исключение: причина — из истории, утвердил — тот, кто перевёл, дата пересмотра принятия
риска — через 90 дней после миграции.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-05 18:10:00
"""

import json
from datetime import UTC, date, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

LEGACY_REVIEW_DAYS = 90


def upgrade() -> None:
    op.create_table(
        "ticket_exceptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("ticket_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("measures", sa.Text(), nullable=False),
        sa.Column("review_on", sa.Date(), nullable=True),
        sa.Column("requested_by", sa.Integer(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approver_id", sa.Integer(), nullable=True),
        sa.Column("decided_by", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=False),
        sa.Column("ended_by", sa.Integer(), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_reason", sa.Text(), nullable=False),
        sa.Column("prev_status", sa.String(length=32), nullable=False),
        sa.Column("hosts", sa.JSON(), nullable=False),
        sa.Column("vuln_count", sa.Integer(), nullable=False),
        sa.Column("extensions", sa.JSON(), nullable=False),
        sa.Column("sync_scanner", sa.Boolean(), nullable=False),
        sa.Column("sync", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approver_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ended_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ticket_id"], ["tickets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exceptions_project_status", "ticket_exceptions", ["project_id", "status"], unique=False)
    op.create_index(op.f("ix_ticket_exceptions_ticket_id"), "ticket_exceptions", ["ticket_id"], unique=False)
    with op.batch_alter_table("scanner_sources") as batch:
        batch.add_column(sa.Column("sync_false_positives", sa.Boolean(), nullable=False, server_default=sa.false()))
    _migrate_legacy()


def _migrate_legacy() -> None:
    """Исключения этапа 1 (статус заявки без записи об исключении) → действующие исключения."""
    conn = op.get_bind()
    now = datetime.now(UTC)
    review = date.today() + timedelta(days=LEGACY_REVIEW_DAYS)
    tickets = conn.execute(
        sa.text(
            "SELECT id, project_id, status, closed_at FROM tickets "
            "WHERE status IN ('risk_accepted', 'false_positive') ORDER BY id"
        )
    ).all()
    json_cols = {"hosts", "extensions", "sync"}
    names = (
        "project_id ticket_id kind status reason measures review_on requested_by requested_at approver_id "
        "decided_by decided_at decision_note ended_by ended_at end_reason prev_status hosts vuln_count "
        "extensions sync_scanner sync created_at updated_at"
    ).split()
    types = {
        "review_on": sa.Date(),
        "requested_at": sa.DateTime(timezone=True),
        "decided_at": sa.DateTime(timezone=True),
        "created_at": sa.DateTime(timezone=True),
        "updated_at": sa.DateTime(timezone=True),
        "sync_scanner": sa.Boolean(),
    }
    table = sa.table(
        "ticket_exceptions",
        *[sa.column(c, sa.JSON() if c in json_cols else types.get(c)) for c in names],
    )
    for tid, project_id, status, closed_at in tickets:
        h = conn.execute(
            sa.text(
                "SELECT actor_id, from_value, details, at FROM ticket_history "
                "WHERE ticket_id = :t AND action = 'status' AND to_value = :s ORDER BY id DESC LIMIT 1"
            ),
            {"t": tid, "s": status},
        ).first()
        details = h.details if h else None
        if isinstance(details, str):
            details = json.loads(details)
        reason = ((details or {}).get("reason") or "").strip() or "Исключение этапа 1 (причина не сохранилась)"
        hosts = [
            r[0]
            for r in conn.execute(
                sa.text("SELECT host FROM ticket_hosts WHERE ticket_id = :t ORDER BY host"), {"t": tid}
            )
        ]
        vulns = conn.execute(sa.text("SELECT count(*) FROM vulnerabilities WHERE ticket_id = :t"), {"t": tid}).scalar()
        at = (h.at if h else None) or closed_at or now
        if isinstance(at, str):  # SQLite отдаёт даты строкой
            at = datetime.fromisoformat(at)
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        conn.execute(
            table.insert().values(
                project_id=project_id,
                ticket_id=tid,
                kind=status,
                status="active",
                reason=reason,
                measures="",
                review_on=review if status == "risk_accepted" else None,
                requested_by=h.actor_id if h else None,
                requested_at=at,
                approver_id=h.actor_id if h else None,
                decided_by=h.actor_id if h else None,
                decided_at=at,
                decision_note="Перенесено из этапа 1: исключение поставил руководитель без отдельного утверждения",
                ended_by=None,
                ended_at=None,
                end_reason="",
                prev_status=(h.from_value if h else "") or "",
                hosts=hosts,
                vuln_count=vulns or 0,
                extensions=[],
                sync_scanner=False,
                sync={},
                created_at=now,
                updated_at=now,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scanner_sources") as batch:
        batch.drop_column("sync_false_positives")
    op.drop_index(op.f("ix_ticket_exceptions_ticket_id"), table_name="ticket_exceptions")
    op.drop_index("ix_exceptions_project_status", table_name="ticket_exceptions")
    op.drop_table("ticket_exceptions")
