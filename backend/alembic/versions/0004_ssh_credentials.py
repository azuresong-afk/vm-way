"""SSH-учётки проекта и закреплённые ключи хостов (задача 2.3).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-05 12:30:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ssh_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("auth", sa.String(length=16), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("become", sa.String(length=8), nullable=False),
        sa.Column("secret_enc", sa.Text(), nullable=False),
        sa.Column("key_type", sa.String(length=64), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=100), nullable=False),
        sa.Column("has_become_password", sa.Boolean(), nullable=False),
        sa.Column("hosts", sa.JSON(), nullable=False),
        sa.Column("groups", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_host", sa.String(length=255), nullable=False),
        sa.Column("last_check_result", sa.String(length=32), nullable=False),
        sa.Column("last_check_message", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_ssh_credential_project_name"),
    )
    op.create_index(op.f("ix_ssh_credentials_project_id"), "ssh_credentials", ["project_id"], unique=False)
    op.create_table(
        "host_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("key_type", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=100), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("pinned_via", sa.String(length=16), nullable=False),
        sa.Column("pinned_by", sa.Integer(), nullable=True),
        sa.Column("pinned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mismatch_key_type", sa.String(length=64), nullable=False),
        sa.Column("mismatch_fingerprint", sa.String(length=100), nullable=False),
        sa.Column("mismatch_public_key", sa.Text(), nullable=False),
        sa.Column("mismatch_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mismatch_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["pinned_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "host", "port", name="uq_host_key_project_host_port"),
    )
    op.create_index(op.f("ix_host_keys_project_id"), "host_keys", ["project_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_host_keys_project_id"), table_name="host_keys")
    op.drop_table("host_keys")
    op.drop_index(op.f("ix_ssh_credentials_project_id"), table_name="ssh_credentials")
    op.drop_table("ssh_credentials")
