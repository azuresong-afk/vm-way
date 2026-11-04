"""Окна обслуживания (задача 2.1): таблица окон и окно у заявки.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-04 21:40:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("weekdays", sa.JSON(), nullable=False),
        sa.Column("start_time", sa.String(length=5), nullable=False),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=True),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("hosts", sa.JSON(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_maintenance_windows_project_id"), "maintenance_windows", ["project_id"], unique=False)
    with op.batch_alter_table("tickets") as batch:
        batch.add_column(sa.Column("window_id", sa.Integer(), nullable=True))
        batch.create_index(batch.f("ix_tickets_window_id"), ["window_id"], unique=False)
        batch.create_foreign_key(
            "fk_tickets_window_id", "maintenance_windows", ["window_id"], ["id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("tickets") as batch:
        batch.drop_constraint("fk_tickets_window_id", type_="foreignkey")
        batch.drop_index(batch.f("ix_tickets_window_id"))
        batch.drop_column("window_id")
    op.drop_index(op.f("ix_maintenance_windows_project_id"), table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
