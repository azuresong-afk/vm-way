"""Раскатки (задача 2.4): задания, хосты, журнал команд; параллельность раскаток в проекте.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-05 16:03:33
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rollouts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("ticket_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("template", sa.String(length=16), nullable=False),
        sa.Column("manager", sa.String(length=16), nullable=False),
        sa.Column("packages", sa.JSON(), nullable=False),
        sa.Column("fixed_version", sa.String(length=200), nullable=False),
        sa.Column("service", sa.String(length=200), nullable=False),
        sa.Column("command", sa.JSON(), nullable=False),
        sa.Column("window_id", sa.Integer(), nullable=True),
        sa.Column("canary_host", sa.String(length=255), nullable=False),
        sa.Column("batch_percent", sa.Integer(), nullable=False),
        sa.Column("failure_threshold", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("prepared_by", sa.Integer(), nullable=True),
        sa.Column("dry_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dry_run_by", sa.Integer(), nullable=True),
        sa.Column("decided_by", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=False),
        sa.Column("allow_reboot", sa.Boolean(), nullable=False),
        sa.Column("outside_window", sa.Boolean(), nullable=False),
        sa.Column("outside_window_reason", sa.Text(), nullable=False),
        sa.Column("custom_approved", sa.Boolean(), nullable=False),
        sa.Column("started_by", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stop_requested", sa.Boolean(), nullable=False),
        sa.Column("stopped_by", sa.Integer(), nullable=True),
        sa.Column("stop_reason", sa.Text(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("verification_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["dry_run_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["prepared_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["started_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["stopped_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ticket_id"], ["tickets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["window_id"], ["maintenance_windows.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rollouts_project_status", "rollouts", ["project_id", "status"], unique=False)
    op.create_index(op.f("ix_rollouts_ticket_id"), "rollouts", ["ticket_id"], unique=False)
    op.create_table(
        "rollout_hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rollout_id", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("stage", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("credential_name", sa.String(length=200), nullable=False),
        sa.Column("dry_status", sa.String(length=16), nullable=False),
        sa.Column("dry_plan", sa.JSON(), nullable=False),
        sa.Column("dry_note", sa.Text(), nullable=False),
        sa.Column("versions_before", sa.JSON(), nullable=False),
        sa.Column("versions_after", sa.JSON(), nullable=False),
        sa.Column("reboot_required", sa.Boolean(), nullable=False),
        sa.Column("rebooted", sa.Boolean(), nullable=False),
        sa.Column("kernel_before", sa.String(length=200), nullable=False),
        sa.Column("kernel_after", sa.String(length=200), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["credential_id"], ["ssh_credentials.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rollout_id"], ["rollouts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rollout_id", "host", name="uq_rollout_host"),
    )
    op.create_index(op.f("ix_rollout_hosts_rollout_id"), "rollout_hosts", ["rollout_id"], unique=False)
    op.create_table(
        "rollout_steps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rollout_id", sa.Integer(), nullable=False),
        sa.Column("rollout_host_id", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("returncode", sa.Integer(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("stdout", sa.Text(), nullable=False),
        sa.Column("stderr", sa.Text(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["rollout_host_id"], ["rollout_hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rollout_id"], ["rollouts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_rollout_steps_rollout_host_id"), "rollout_steps", ["rollout_host_id"], unique=False)
    op.create_index(op.f("ix_rollout_steps_rollout_id"), "rollout_steps", ["rollout_id"], unique=False)
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("rollout_parallelism", sa.Integer(), nullable=False, server_default="5"))


def downgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("rollout_parallelism")
    op.drop_index(op.f("ix_rollout_steps_rollout_id"), table_name="rollout_steps")
    op.drop_index(op.f("ix_rollout_steps_rollout_host_id"), table_name="rollout_steps")
    op.drop_table("rollout_steps")
    op.drop_index(op.f("ix_rollout_hosts_rollout_id"), table_name="rollout_hosts")
    op.drop_table("rollout_hosts")
    op.drop_index(op.f("ix_rollouts_ticket_id"), table_name="rollouts")
    op.drop_index("ix_rollouts_project_status", table_name="rollouts")
    op.drop_table("rollouts")
