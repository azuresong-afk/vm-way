"""Модель данных «Устранения»: этап 1 и этап 2 (окна, активы, правила, SSH, раскатки, исключения)."""

import uuid
from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base, utcnow


def new_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    email: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    roles: Mapped[list] = mapped_column(JSON, default=list)
    extra_perms: Mapped[list] = mapped_column(JSON, default=list)
    platform_sub: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200))
    client: Mapped[str] = mapped_column(String(200), default="")
    contract_ref: Mapped[str] = mapped_column(String(200), default="")
    period_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    period_to: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    platform_project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    # Сколько хостов проекта раскатка (задача 2.4) обрабатывает одновременно.
    rollout_parallelism: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScannerSource(Base):
    __tablename__ = "scanner_sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    base_url: Mapped[str] = mapped_column(String(500))
    web_url: Mapped[str] = mapped_column(String(500), default="")
    username: Mapped[str] = mapped_column(String(200), default="")
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_import: Mapped[bool] = mapped_column(Boolean, default=True)
    poll_minutes: Mapped[int] = mapped_column(Integer, default=15)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    # Отмечать ложные срабатывания в «Сканере» (задача 2.5). Выключено по умолчанию: сервисной
    # учётке нужна роль operator (право triage_findings).
    sync_false_positives: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceLink(Base):
    __tablename__ = "source_links"
    __table_args__ = (UniqueConstraint("source_id", "engagement_id", name="uq_link_source_engagement"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("scanner_sources.id", ondelete="CASCADE"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[int] = mapped_column(Integer)
    engagement_name: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[ScannerSource] = relationship()


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (UniqueConstraint("source_id", "scanner_run_id", name="uq_run_source_run"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("scanner_sources.id", ondelete="CASCADE"))
    link_id: Mapped[int | None] = mapped_column(ForeignKey("source_links.id", ondelete="SET NULL"), nullable=True)
    scanner_run_id: Mapped[int] = mapped_column(Integer)
    engagement_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(300), default="")
    kind: Mapped[str] = mapped_column(String(16), default="scheduled")  # scheduled | verification
    status: Mapped[str] = mapped_column(String(16))
    modules: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_by: Mapped[str] = mapped_column(String(64), default="")
    stats: Mapped[dict] = mapped_column(JSON, default=dict)


class RunCoverage(Base):
    __tablename__ = "run_coverage"
    __table_args__ = (UniqueConstraint("run_id", "host", "module", name="uq_cov"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    module: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")


class MaintenanceWindow(Base):
    """Окно обслуживания (задача 2.1): разовое, повторяющееся или блэкаут.

    Разовое окно и блэкаут — интервал `starts_at…ends_at`. Повторяющееся — дни недели
    (`weekdays`, 0 — понедельник), время начала `start_time` («22:00») в часовом поясе окна
    и длительность; действует с `valid_from` по `valid_until` включительно. Охват — хосты
    (`hosts`); пустой список — все хосты проекта."""

    __tablename__ = "maintenance_windows"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))  # once | recurring | blackout
    timezone: Mapped[str] = mapped_column(String(64), default="Europe/Moscow")
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    weekdays: Mapped[list] = mapped_column(JSON, default=list)
    start_time: Mapped[str] = mapped_column(String(5), default="")
    duration_minutes: Mapped[int] = mapped_column(Integer, default=0)
    valid_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    # Группы активов «Сканера» по имени (задача 2.2): охват — хосты списка плюс хосты групп.
    groups: Mapped[list] = mapped_column(JSON, default=list)
    note: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    """Актив «Сканера» (задача 2.2) — копия для правил назначения, фильтров и охвата окон.

    Ключ сопоставления с хостами заявок — `(project_id, address)`, как в контракте платформы.
    Источник истины — «Сканер»: строки перезаписываются при каждой синхронизации."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "address", name="uq_asset_project_address"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("scanner_sources.id", ondelete="SET NULL"), nullable=True)
    engagement_id: Mapped[int] = mapped_column(Integer)
    scanner_asset_id: Mapped[int] = mapped_column(Integer)
    address: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(253), default="")
    owner: Mapped[str] = mapped_column(String(256), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    os_family: Mapped[str] = mapped_column(String(64), default="")
    os_guess: Mapped[str] = mapped_column(String(200), default="")
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    groups: Mapped[list["AssetGroup"]] = relationship(
        secondary="asset_group_members", back_populates="assets", order_by="AssetGroup.name"
    )


class AssetGroup(Base):
    """Группа активов «Сканера». Группы с одинаковым именем из разных проектов «Сканера» сливаются."""

    __tablename__ = "asset_groups"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_asset_group_project_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assets: Mapped[list[Asset]] = relationship(secondary="asset_group_members", back_populates="groups")


class AssetGroupMember(Base):
    __tablename__ = "asset_group_members"
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True)


class Team(Base):
    """Команда исполнителей (задача 2.2): цель правила назначения с распределением по загрузке."""

    __tablename__ = "teams"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    members: Mapped[list[User]] = relationship(secondary="team_members", order_by="User.id")


class TeamMember(Base):
    __tablename__ = "team_members"
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class AssignmentRule(Base):
    """Правило назначения (задача 2.2). Правила проверяются по порядку `position`, срабатывает первое.

    Условия: внутри списка — «любое из», между списками — «и», пустой список — «любое значение».
    Группа, тег и владелец — свойства хостов заявки (`host_match`: все хосты или хотя бы один),
    ОС и вид — свойства самой заявки. Цель — исполнитель или команда (по загрузке)."""

    __tablename__ = "assignment_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    owners: Mapped[list] = mapped_column(JSON, default=list)
    os: Mapped[list] = mapped_column(JSON, default=list)
    kinds: Mapped[list] = mapped_column(JSON, default=list)
    host_match: Mapped[str] = mapped_column(String(8), default="all")  # all | any
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    team_id: Mapped[int | None] = mapped_column(ForeignKey("teams.id", ondelete="RESTRICT"), nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id])
    team: Mapped[Team | None] = relationship()


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = (
        Index("ix_tickets_project_status", "project_id", "status"),
        Index("ix_tickets_project_fix", "project_id", "fix_key"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fix_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(32), default="other")
    scanner_kind: Mapped[str] = mapped_column(String(32), default="")
    os: Mapped[str] = mapped_column(String(120), default="")
    os_family: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    severity_override: Mapped[str | None] = mapped_column(String(16), nullable=True)
    priority_rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority_label: Mapped[str] = mapped_column(String(64), default="")
    priority_override: Mapped[str | None] = mapped_column(String(64), nullable=True)
    override_reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="new")
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_regression: Mapped[bool] = mapped_column(Boolean, default=False)
    # Окно обслуживания, в которое поставлена заявка (задача 2.1).
    window_id: Mapped[int | None] = mapped_column(
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id])
    window: Mapped["MaintenanceWindow | None"] = relationship()
    hosts: Mapped[list["TicketHost"]] = relationship(
        back_populates="ticket", cascade="all, delete-orphan", order_by="TicketHost.host"
    )

    @property
    def effective_severity(self) -> str:
        return self.severity_override or self.severity


class TicketHost(Base):
    __tablename__ = "ticket_hosts"
    __table_args__ = (UniqueConstraint("ticket_id", "host", name="uq_ticket_host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    installed: Mapped[str] = mapped_column(String(200), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")  # open|confirmed|not_confirmed|unverified
    reason: Mapped[str] = mapped_column(Text, default="")
    last_check_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ticket: Mapped[Ticket] = relationship(back_populates="hosts")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("project_id", "dedup_key", name="uq_vuln_project_dedup"),
        Index("ix_vuln_project_state", "project_id", "state"),
        Index("ix_vuln_project_host", "project_id", "host"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    dedup_key: Mapped[str] = mapped_column(String(128))
    scanner_finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("scanner_sources.id", ondelete="SET NULL"), nullable=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    module: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(32), default="vuln")
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    priority: Mapped[dict] = mapped_column(JSON, default=dict)
    vuln_id: Mapped[str] = mapped_column(String(200), default="")
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    bdu_ids: Mapped[list] = mapped_column(JSON, default=list)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    software: Mapped[str] = mapped_column(String(200), default="")
    software_version: Mapped[str] = mapped_column(String(200), default="")
    confidence: Mapped[str] = mapped_column(String(16), default="")
    scanner_status: Mapped[str] = mapped_column(String(16), default="")
    state: Mapped[str] = mapped_column(String(16), default="open")  # open | fixed
    is_regression: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ticket_id: Mapped[int | None] = mapped_column(
        ForeignKey("tickets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    first_seen_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    fixed_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VulnerabilityEvent(Base):
    __tablename__ = "vulnerability_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    event: Mapped[str] = mapped_column(String(32))  # appeared | fixed | regression | still_present
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketWatcher(Base):
    __tablename__ = "ticket_watchers"
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="user")  # user | system
    body: Mapped[str] = mapped_column(Text)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    author: Mapped[User | None] = relationship()


class TicketHistory(Base):
    __tablename__ = "ticket_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    from_value: Mapped[str] = mapped_column(String(200), default="")
    to_value: Mapped[str] = mapped_column(String(200), default="")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[User | None] = relationship()


class Verification(Base):
    __tablename__ = "verifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    source_id: Mapped[int] = mapped_column(ForeignKey("scanner_sources.id", ondelete="CASCADE"))
    engagement_id: Mapped[int] = mapped_column(Integer)
    scanner_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="requested")  # requested|running|done|failed
    targets: Mapped[list] = mapped_column(JSON, default=list)
    denied_targets: Mapped[list] = mapped_column(JSON, default=list)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_at", "at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_sub: Mapped[str] = mapped_column(String(64), default="")
    username: Mapped[str] = mapped_column(String(200), default="")
    product: Mapped[str] = mapped_column(String(16), default="vm")
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str] = mapped_column(String(64), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    result: Mapped[str] = mapped_column(String(16), default="ok")  # ok | denied | error
    ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    type: Mapped[str] = mapped_column(String(64))
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    subject: Mapped[str] = mapped_column(String(128), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SshCredential(Base):
    """SSH-учётка проекта (задача 2.3): логин и пароль или закрытый ключ, повышение прав через sudo.

    Секреты (`password`, `private_key`, `passphrase`, `become_password`) лежат только в `secret_enc` —
    JSON, зашифрованный AES-GCM ключом `VM_ENCRYPTION_KEY` и привязанный к id учётки. API их не отдаёт.
    Охват — адреса и подсети (`hosts`) и группы активов «Сканера» (`groups`); пустой — все хосты
    проекта."""

    __tablename__ = "ssh_credentials"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_ssh_credential_project_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    username: Mapped[str] = mapped_column(String(128))
    auth: Mapped[str] = mapped_column(String(16), default="password")  # password | key
    port: Mapped[int] = mapped_column(Integer, default=22)
    become: Mapped[str] = mapped_column(String(8), default="sudo")  # sudo | none
    secret_enc: Mapped[str] = mapped_column(Text, default="")
    key_type: Mapped[str] = mapped_column(String(64), default="")
    key_fingerprint: Mapped[str] = mapped_column(String(100), default="")
    has_become_password: Mapped[bool] = mapped_column(Boolean, default=False)
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_host: Mapped[str] = mapped_column(String(255), default="")
    last_check_result: Mapped[str] = mapped_column(String(32), default="")
    last_check_message: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HostKey(Base):
    """Закреплённый ключ хоста (TOFU, задача 2.3) — по проекту, адресу и порту.

    Первое подключение запоминает ключ (`pinned_via=tofu`); другой ключ — отказ до входа, ключ
    записывается в `mismatch_*`, статус `mismatch`, и подключения к хосту запрещены, пока
    руководитель не примет новый ключ или не сбросит закрепление."""

    __tablename__ = "host_keys"
    __table_args__ = (UniqueConstraint("project_id", "host", "port", name="uq_host_key_project_host_port"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    key_type: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(100))
    public_key: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pinned")  # pinned | mismatch
    pinned_via: Mapped[str] = mapped_column(String(16), default="tofu")  # tofu | accepted
    pinned_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mismatch_key_type: Mapped[str] = mapped_column(String(64), default="")
    mismatch_fingerprint: Mapped[str] = mapped_column(String(100), default="")
    mismatch_public_key: Mapped[str] = mapped_column(Text, default="")
    mismatch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mismatch_count: Mapped[int] = mapped_column(Integer, default=0)


class Rollout(Base):
    """Раскатка (задача 2.4) — изменение на хостах заявки по шаблону.

    Этапы: пробный прогон → утверждение вторым человеком → канарейка → партии → повторная проверка.
    Параметры задаются при подготовке и дальше не меняются: другое изменение — новая раскатка."""

    __tablename__ = "rollouts"
    __table_args__ = (Index("ix_rollouts_project_status", "project_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(500))
    template: Mapped[str] = mapped_column(String(16))  # package | kernel | service | custom
    manager: Mapped[str] = mapped_column(String(16), default="")  # apt | apt-rpm | dnf | yum | zypper | apk
    packages: Mapped[list] = mapped_column(JSON, default=list)
    fixed_version: Mapped[str] = mapped_column(String(200), default="")
    service: Mapped[str] = mapped_column(String(200), default="")
    command: Mapped[list] = mapped_column(JSON, default=list)  # произвольная команда списком аргументов
    window_id: Mapped[int | None] = mapped_column(
        ForeignKey("maintenance_windows.id", ondelete="SET NULL"), nullable=True
    )
    canary_host: Mapped[str] = mapped_column(String(255), default="")
    batch_percent: Mapped[int] = mapped_column(Integer, default=10)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=10)  # % ошибок, после которого стоп
    status: Mapped[str] = mapped_column(String(24), default="draft")
    error: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(Text, default="")
    prepared_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    dry_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dry_run_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # Решение руководителя: утверждение (с разрешениями) или отказ — с комментарием.
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    allow_reboot: Mapped[bool] = mapped_column(Boolean, default=False)
    outside_window: Mapped[bool] = mapped_column(Boolean, default=False)
    outside_window_reason: Mapped[str] = mapped_column(Text, default="")
    custom_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    started_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    stopped_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    stop_reason: Mapped[str] = mapped_column(Text, default="")
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verification_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    hosts: Mapped[list["RolloutHost"]] = relationship(
        back_populates="rollout", cascade="all, delete-orphan", order_by="RolloutHost.id"
    )


class RolloutHost(Base):
    """Хост раскатки: этап (0 — канарейка, 1… — партии), итог, версии «до/после», перезагрузка."""

    __tablename__ = "rollout_hosts"
    __table_args__ = (UniqueConstraint("rollout_id", "host", name="uq_rollout_host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rollout_id: Mapped[int] = mapped_column(ForeignKey("rollouts.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    stage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    reason: Mapped[str] = mapped_column(Text, default="")
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("ssh_credentials.id", ondelete="SET NULL"), nullable=True
    )
    credential_name: Mapped[str] = mapped_column(String(200), default="")
    dry_status: Mapped[str] = mapped_column(String(16), default="")  # ok | failed
    dry_plan: Mapped[list] = mapped_column(JSON, default=list)  # [{package, from, to}]
    dry_note: Mapped[str] = mapped_column(Text, default="")
    versions_before: Mapped[dict] = mapped_column(JSON, default=dict)
    versions_after: Mapped[dict] = mapped_column(JSON, default=dict)
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    rebooted: Mapped[bool] = mapped_column(Boolean, default=False)
    kernel_before: Mapped[str] = mapped_column(String(200), default="")
    kernel_after: Mapped[str] = mapped_column(String(200), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rollout: Mapped[Rollout] = relationship(back_populates="hosts")


class RolloutStep(Base):
    """Строка журнала раскатки: команда на хосте, код возврата, stdout/stderr и длительность."""

    __tablename__ = "rollout_steps"
    id: Mapped[int] = mapped_column(primary_key=True)
    rollout_id: Mapped[int] = mapped_column(ForeignKey("rollouts.id", ondelete="CASCADE"), index=True)
    rollout_host_id: Mapped[int] = mapped_column(ForeignKey("rollout_hosts.id", ondelete="CASCADE"), index=True)
    phase: Mapped[str] = mapped_column(String(16))  # dry_run | execute
    label: Mapped[str] = mapped_column(String(200))
    command: Mapped[str] = mapped_column(Text, default="")
    returncode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketException(Base):
    """Исключение по заявке (задача 2.5): принятие риска или ложное срабатывание.

    Жизненный цикл: pending (ждёт утверждающего) → active (заявка в статусе исключения) →
    revoked (снято досрочно) | expired (прошла дата пересмотра). Из pending — rejected или withdrawn.
    У заявки одновременно не больше одного исключения в pending/active.
    """

    __tablename__ = "ticket_exceptions"
    __table_args__ = (Index("ix_exceptions_project_status", "project_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # risk_accepted | false_positive
    status: Mapped[str] = mapped_column(String(16), default="pending")
    reason: Mapped[str] = mapped_column(Text)
    measures: Mapped[str] = mapped_column(Text, default="")  # компенсирующие меры
    review_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    ended_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_reason: Mapped[str] = mapped_column(Text, default="")
    # Статус заявки до исключения и хосты на момент утверждения.
    prev_status: Mapped[str] = mapped_column(String(32), default="")
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    extensions: Mapped[list] = mapped_column(JSON, default=list)
    # Отметка ложного срабатывания в «Сканере»: просили ли и что вышло.
    sync_scanner: Mapped[bool] = mapped_column(Boolean, default=False)
    sync: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    ticket: Mapped[Ticket] = relationship()
    requester: Mapped[User | None] = relationship(foreign_keys=[requested_by])
    approver: Mapped[User | None] = relationship(foreign_keys=[approver_id])
    decider: Mapped[User | None] = relationship(foreign_keys=[decided_by])
    ender: Mapped[User | None] = relationship(foreign_keys=[ended_by])
