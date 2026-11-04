"""Схемы ответов API «Сканера», переписанные из scanner-way (scanner/api/schemas.py).

Нужны, чтобы мок и демо-фикстура не разошлись с настоящим API: тест прогоняет ответы мока
через эти схемы с запретом лишних полей. При изменении API «Сканера» обновите схемы здесь.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MeOut(_Strict):
    id: int
    username: str
    display_name: str | None
    is_active: bool
    roles: list[str]
    permissions: list[str]


class EngagementOut(_Strict):
    id: int
    name: str
    client: str | None
    contract_ref: str | None
    created_by: int | None
    created_at: datetime | None


class AllowlistOut(_Strict):
    id: int
    cidr: str
    note: str | None
    added_by: int | None
    added_at: datetime | None
    range_spec: str | None = None


class RunOut(_Strict):
    id: int
    engagement_id: int
    modules: list[str]
    rate_profile: str
    credential_ids: list[int]
    cred_set_ids: list[int]
    name: str | None = None
    targets: list[str]
    schedule_id: int | None = None
    status: str
    started_by: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime | None
    error_message: str | None = None
    retry_of: int | None = None
    options: dict
    warnings: list[dict]
    progress: dict | None = None


class DeniedTargetOut(_Strict):
    target: str
    reason: str
    count: int = 1


class RunCreated(RunOut):
    accepted_targets: int
    denied_targets: list[DeniedTargetOut]


class PriorityOut(_Strict):
    rank: int
    score: float
    label: str
    label_ru: str
    reasons: list[str]
    factors: dict


class FalsePositiveMarkOut(_Strict):
    reason: str | None
    marked_by: str | None
    marked_at: datetime | None


class FindingOut(_Strict):
    id: int
    dedup_key: str
    module: str
    host: str
    port: int | None
    finding_type: str
    title: str
    severity: str
    vuln_id: str | None
    cve_ids: list[str]
    bdu_ids: list[str]
    cvss: float | None
    evidence: str | None
    status: str | None
    detected_at: datetime
    false_positive: FalsePositiveMarkOut | None = None
    software: str | None = None
    software_version: str | None = None
    software_source: str | None = None
    priority: PriorityOut | None = None
    confidence: str | None = None
    source: str | None = None


class FixFindingOut(_Strict):
    id: int
    label: str
    severity: str


class FixHostOut(_Strict):
    host: str
    installed: str | None
    note: str | None
    ports: list[int]
    findings: list[FixFindingOut]


class FixPriorityOut(_Strict):
    score: float
    label: str
    label_ru: str
    rank: int | None


class FixTaskOut(_Strict):
    key: str
    kind: str
    kind_label: str
    title: str
    os: str | None
    os_family: str | None
    manager: str | None
    packages: list[str]
    fixed_version: str | None
    software: str | None
    steps: list[str]
    commands: list[str]
    verify: list[str]
    reboot: bool
    details: str | None
    details_source: str | None
    severity: str
    priority: FixPriorityOut | None
    cves: list[str]
    bdu_ids: list[str]
    advisories: list[str]
    references: list[str]
    hosts: list[FixHostOut]
    host_count: int
    finding_count: int


class FixPlanOut(_Strict):
    total: int
    items: list[FixTaskOut]
    tasks: int
    hosts: int
    findings: int
    false_positives: int
    kinds: dict[str, int]
    os: dict[str, int]
    severities: dict[str, int]


class CoverageEntryOut(_Strict):
    host: str
    module: str
    status: str
    label: str
    reason: str | None = None


class CoverageOut(_Strict):
    scan_run_id: int
    status: str
    summary: dict
    hosts: list[dict]
    entries: list[CoverageEntryOut]
    legacy: bool = False


RUN_STATUSES = {"pending", "running", "done", "partial", "failed", "stopped", "interrupted"}
FINDING_STATUSES = {"open", "fixed", "new", "regression"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
COVERAGE_STATUSES = {"completed", "not_applicable", "skipped", "unreachable", "no_credentials", "timeout", "error"}
FIX_KINDS = {"package", "package_nofix", "package_upgrade", "kernel", "software", "config", "cred", "vuln", "other"}
PRIORITY_LABELS = {"critical", "high", "medium", "low"}
