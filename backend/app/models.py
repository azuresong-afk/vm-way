"""Модель данных «Устранения» (этап 1)."""

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
    action: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id])
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
