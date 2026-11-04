"""Активы и группы «Сканера», команды и правила назначения (задача 2.2); группы в охвате окон.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-04 23:00:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("scanner_asset_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("owner", sa.String(length=256), nullable=False),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("os_family", sa.String(length=64), nullable=False),
        sa.Column("os_guess", sa.String(length=200), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["scanner_sources.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "address", name="uq_asset_project_address"),
    )
    op.create_index(op.f("ix_assets_project_id"), "assets", ["project_id"], unique=False)
    op.create_table(
        "asset_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_asset_group_project_name"),
    )
    op.create_index(op.f("ix_asset_groups_project_id"), "asset_groups", ["project_id"], unique=False)
    op.create_table(
        "asset_group_members",
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id", "group_id"),
    )
    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "team_members",
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_id", "user_id"),
    )
    op.create_table(
        "assignment_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("groups", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("owners", sa.JSON(), nullable=False),
        sa.Column("os", sa.JSON(), nullable=False),
        sa.Column("kinds", sa.JSON(), nullable=False),
        sa.Column("host_match", sa.String(length=8), nullable=False),
        sa.Column("assignee_id", sa.Integer(), nullable=True),
        sa.Column("team_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["assignee_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assignment_rules_project_id"), "assignment_rules", ["project_id"], unique=False)
    with op.batch_alter_table("maintenance_windows") as batch:
        batch.add_column(sa.Column("groups", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    with op.batch_alter_table("maintenance_windows") as batch:
        batch.drop_column("groups")
    op.drop_index(op.f("ix_assignment_rules_project_id"), table_name="assignment_rules")
    op.drop_table("assignment_rules")
    op.drop_table("team_members")
    op.drop_table("teams")
    op.drop_table("asset_group_members")
    op.drop_index(op.f("ix_asset_groups_project_id"), table_name="asset_groups")
    op.drop_table("asset_groups")
    op.drop_index(op.f("ix_assets_project_id"), table_name="assets")
    op.drop_table("assets")
