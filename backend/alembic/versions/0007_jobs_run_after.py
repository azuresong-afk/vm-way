"""Фоновые задачи: срок «не раньше» для отложенных вызовов и повторов, индекс для очистки outbox.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-12 08:30:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.add_column(sa.Column("run_after", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_outbox_created_at", "outbox", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_outbox_created_at", table_name="outbox")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_column("run_after")
