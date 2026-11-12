"""Вход (задача Г ревью): счётчик неудачных входов, отозванные токены, обязательная смена пароля.

У существующих пользователей обязательная смена не включается: она появляется, когда администратор
создаёт пользователя или сбрасывает ему пароль.

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
    op.create_table(
        "login_failures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_login_failures_username", "login_failures", ["username"], unique=False)
    op.create_index("ix_login_failures_ip", "login_failures", ["ip"], unique=False)
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("jti"),
    )
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("must_change_password")
    op.drop_table("revoked_tokens")
    op.drop_index("ix_login_failures_ip", table_name="login_failures")
    op.drop_index("ix_login_failures_username", table_name="login_failures")
    op.drop_table("login_failures")
