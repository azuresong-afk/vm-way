"""Вход (задача Г ревью): счётчик неудачных входов, отозванные токены, обязательная смена пароля.

У существующих пользователей обязательная смена не включается: она появляется, когда администратор
создаёт пользователя или сбрасывает ему пароль.

Миграция вышла в PR #19 под номером 0007 — одновременно с 0007 фоновых задач (run_after), и цепочка
разветвилась. База, обновлённая с ветки PR #19, помечена «0007», но в ней таблицы входа, а не
изменения фоновых задач. Поэтому каждый шаг здесь проверяет, что уже есть: в такой базе миграция
доделывает пропущенную 0007 фоновых задач, в обычной — создаёт своё.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-12 22:15:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    tables = set(insp.get_table_names())

    def columns(table: str) -> set[str]:
        return {c["name"] for c in insp.get_columns(table)}

    if "login_failures" not in tables:
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
    if "revoked_tokens" not in tables:
        op.create_table(
            "revoked_tokens",
            sa.Column("jti", sa.String(length=32), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("expires_at", sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint("jti"),
        )
    if "must_change_password" not in columns("users"):
        with op.batch_alter_table("users") as batch:
            batch.add_column(sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))

    # База с прежней «0007» входа: 0007 фоновых задач в ней не применялась — доделываем её шаги.
    if "run_after" not in columns("jobs"):
        with op.batch_alter_table("jobs") as batch:
            batch.add_column(sa.Column("run_after", sa.DateTime(timezone=True), nullable=True))
    if "ix_outbox_created_at" not in {i["name"] for i in insp.get_indexes("outbox")}:
        op.create_index("ix_outbox_created_at", "outbox", ["created_at"])


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("must_change_password")
    op.drop_table("revoked_tokens")
    op.drop_index("ix_login_failures_ip", table_name="login_failures")
    op.drop_index("ix_login_failures_username", table_name="login_failures")
    op.drop_table("login_failures")
