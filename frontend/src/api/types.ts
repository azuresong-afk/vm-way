// Типы ответов API «Устранения» (backend/app/api/*).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type TicketStatus =
  | "new"
  | "assigned"
  | "in_progress"
  | "waiting_window"
  | "fixed"
  | "verified"
  | "not_verified"
  | "risk_accepted"
  | "false_positive"
  | "no_vendor_fix"
  | "regression";

export type Perm =
  | "view"
  | "import"
  | "ticket_work"
  | "ticket_assign"
  | "ticket_override"
  | "verify"
  | "windows_manage"
  | "rules_manage"
  | "credentials_manage"
  | "rollout_approve"
  | "exception_approve"
  | "projects_manage"
  | "sources_manage"
  | "users_manage"
  | "audit_view"
  | "remediate_execute"
  | "custom_commands";

export interface Page<T> {
  items: T[];
  total: number;
}

export interface TokenOut {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface MeOut {
  id: number;
  username: string;
  display_name: string;
  roles: string[];
  role_labels: string[];
  permissions: Perm[];
  projects: string[];
}

export interface ProjectOut {
  id: string;
  name: string;
  client: string;
  contract_ref: string;
  period_from: string | null;
  period_to: string | null;
  status: "active" | "archived";
  platform_project_id: string | null;
  created_at: string;
}

export interface ProjectIn {
  name: string;
  client: string;
  contract_ref: string;
  period_from: string | null;
  period_to: string | null;
  status?: "active" | "archived";
}

export interface UserRef {
  id: number;
  username: string;
  display_name: string;
}

export interface TicketBrief {
  id: number;
  project_id: string;
  title: string;
  kind: string;
  scanner_kind: string;
  os: string;
  os_family: string;
  severity: Severity;
  scanner_severity: Severity;
  severity_overridden: boolean;
  priority: { rank: number | null; label: string };
  status: TicketStatus;
  status_label: string;
  is_regression: boolean;
  assignee: UserRef | null;
  window: { id: number; name: string } | null;
  reboot: boolean;
  hosts_total: number;
  hosts_confirmed: number;
  vulns_open: number;
  vulns_total: number;
  cves: string[];
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface TicketAction {
  kind_label: string | null;
  manager: string | null;
  packages: string[] | null;
  fixed_version: string | null;
  software: string | null;
  steps: string[] | null;
  commands: string[] | null;
  verify: string[] | null;
  reboot: boolean | null;
  details: string | null;
  details_source: string | null;
  cves: string[] | null;
  bdu_ids: string[] | null;
  advisories: string[] | null;
  references: string[] | null;
  scanner_title: string | null;
}

export interface Evidence {
  run_id: number;
  scanner_run_id: number;
  run_name: string;
  kind: string;
  finished_at: string | null;
  url: string | null;
}

export type HostStatus = "open" | "confirmed" | "not_confirmed" | "unverified";

export interface TicketHostOut {
  id: number;
  host: string;
  installed: string;
  note: string;
  status: HostStatus;
  reason: string;
  vulnerability_ids: number[];
  asset: AssetBrief | null;
  last_check: { run_id: number; scanner_run_id: number; finished_at: string | null } | null;
  updated_at: string;
}

export interface VulnOut {
  id: number;
  dedup_key: string;
  host: string;
  port: number | null;
  module: string;
  finding_type: string;
  title: string;
  severity: Severity;
  priority: { rank?: number; score?: number; label?: string; label_ru?: string; reasons?: string[] } | null;
  vuln_id: string;
  cve_ids: string[];
  bdu_ids: string[];
  cvss: number | null;
  software: string;
  software_version: string;
  confidence: string;
  state: "open" | "fixed";
  is_regression: boolean;
  ticket_id: number | null;
  scanner_finding_id: number | null;
  first_seen_at: string;
  last_seen_at: string;
  fixed_at: string | null;
}

export interface HostResult {
  host: string;
  status: "confirmed" | "not_confirmed" | "unverified";
  reason: string;
}

export interface VerificationOut {
  id: number;
  ticket_id: number;
  project_id: string;
  source_id: number | null;
  engagement_id: number | null;
  scanner_run_id: number | null;
  run_id: number | null;
  status: "requested" | "running" | "done" | "failed";
  targets: string[];
  denied_targets: { target: string; reason: string }[] | null;
  modules: string[];
  result: {
    outcome?: "verified" | "not_verified" | "partial" | "unverified";
    hosts?: HostResult[];
    counts?: { confirmed: number; not_confirmed: number; unverified: number };
    job_id?: number;
  } | null;
  error: string | null;
  requested_by: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface TicketCan {
  statuses: TicketStatus[];
  take: boolean;
  assign: boolean;
  override: boolean;
  comment: boolean;
  verify: boolean;
  window: boolean;
  rollout: boolean;
  exception: boolean;
}

export interface TicketDetail extends TicketBrief {
  fix_key: string | null;
  action: TicketAction;
  override_reason: string;
  evidence: Evidence | null;
  hosts: TicketHostOut[];
  vulnerabilities: VulnOut[];
  watchers: UserRef[];
  watching: boolean;
  verifications: VerificationOut[];
  rollouts: TicketRolloutBrief[];
  exceptions: ExceptionOut[];
  can: TicketCan;
}

export interface HistoryEntry {
  id: number;
  at: string;
  actor: UserRef | null;
  action: string;
  from: string;
  to: string;
  details: Record<string, unknown> | null;
}

export interface CommentOut {
  id: number;
  at: string;
  author: UserRef | null;
  kind: "user" | "system" | string;
  body: string;
  data: Record<string, unknown> | null;
}

export interface TicketHistoryOut {
  history: HistoryEntry[];
  comments: CommentOut[];
}

export interface TicketMeta {
  statuses: { id: TicketStatus; label: string; open: boolean }[];
  kinds: { id: string; label: string }[];
  severities: Severity[];
}

export interface TicketQuery {
  status?: TicketStatus[];
  state?: "open" | "closed";
  severity?: Severity[];
  kind?: string[];
  os?: string[];
  assignee?: string;
  window?: string;
  host?: string;
  group?: string;
  q?: string;
  sort?: "priority" | "severity" | "created" | "updated" | "title" | "hosts";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface TicketFacets {
  os: { id: string; total: number; open: number }[];
  kinds: { id: string; total: number; open: number }[];
  groups: { id: string; total: number; open: number }[];
}

export interface AssignableUser extends UserRef {
  roles: string[];
  open_tickets?: number;
}

export interface BulkOut {
  changed: number[];
  unchanged: number[];
  failed: { id: number; error: string }[];
}

export type SevCounts = Record<Severity, number>;

export interface SummaryOut {
  period: "3m" | "1y";
  period_start: string;
  generated_at: string;
  open_tickets: number;
  open_vulns: number;
  open_vulns_at_start: number;
  delta: number;
  opened: number;
  closed: number;
  tickets_by_severity: SevCounts;
  vulns_by_severity: SevCounts;
  opened_by_severity: SevCounts;
  closed_by_severity: SevCounts;
  by_status: Record<TicketStatus, number>;
  unassigned: number;
  awaiting_check: number;
  weeks: { start: string; opened: SevCounts; closed: SevCounts }[];
  mttr: { severity: Severity; days: number | null; count: number }[];
  upcoming_windows: CalendarItem[];
  top_hosts: { host: string; open: number; by_severity: SevCounts; tickets: number }[];
  recent_verified: {
    id: number;
    title: string;
    severity: Severity;
    closed_at: string | null;
    hosts: number;
    evidence: Evidence | null;
  }[];
  last_run: { id: number; scanner_run_id: number; name: string; kind: string; finished_at: string | null } | null;
}

export interface SearchOut {
  q: string;
  counts: { tickets: number; hosts: number; vulns: number };
  tickets: {
    id: number;
    project_id: string;
    title: string;
    severity: Severity;
    status: TicketStatus;
    status_label: string;
    os: string;
    url: string;
  }[];
  hosts: { host: string; project_id: string; open: number; max_severity: Severity | null; url: string }[];
  vulns: {
    id: string;
    title: string;
    severity: Severity;
    cves: string[];
    bdu_ids: string[];
    open: number;
    host_count: number;
    ticket_id: number | null;
    project_id: string;
    url: string;
  }[];
}

export interface JobOut {
  id: number;
  kind: string;
  project_id: string | null;
  title: string;
  status: "queued" | "running" | "done" | "failed";
  result: Record<string, unknown> | null;
  error: string | null;
  attempts: number;
  created_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface RunOut {
  id: number;
  project_id: string;
  source_id: number;
  scanner_run_id: number;
  engagement_id: number;
  name: string;
  kind: "scheduled" | "verification";
  status: string;
  modules: string[];
  started_at: string | null;
  finished_at: string | null;
  imported_at: string;
  imported_by: string | null;
  stats: Record<string, number> | null;
}

export interface UserOut {
  id: number;
  username: string;
  display_name: string;
  email: string;
  roles: string[];
  extra_perms: string[];
  is_active: boolean;
  created_at: string;
}

export interface UserCreate {
  username: string;
  display_name: string;
  email: string;
  password: string;
  roles: string[];
  extra_perms: string[];
}

export interface UserPatch {
  display_name?: string;
  email?: string;
  roles?: string[];
  extra_perms?: string[];
  is_active?: boolean;
}

export interface RolesOut {
  roles: { id: string; label: string; perms: string[] }[];
  extra_perms: { id: string; label: string }[];
}

export interface SourceOut {
  id: number;
  name: string;
  base_url: string;
  web_url: string;
  username: string;
  has_password: boolean;
  verify_tls: boolean;
  auto_import: boolean;
  poll_minutes: number;
  sync_false_positives: boolean;
  last_poll_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface SourceIn {
  name: string;
  base_url: string;
  web_url: string;
  username: string;
  password?: string;
  verify_tls: boolean;
  auto_import: boolean;
  poll_minutes: number;
  sync_false_positives?: boolean;
}

export interface SourceTestOut {
  ok: boolean;
  error?: string;
  username?: string;
  roles?: string[];
  warnings?: string[];
}

export interface EngagementOut {
  id: number;
  name: string;
  client: string | null;
  contract_ref: string | null;
  linked_project_id: string | null;
}

export interface LinkOut {
  id: number;
  source_id: number;
  source_name: string;
  project_id: string;
  engagement_id: number;
  engagement_name: string;
  created_at: string;
}

export interface AuditOut {
  id: number;
  at: string;
  user_id: number | null;
  user_sub: string | null;
  username: string | null;
  product: string;
  action: string;
  object_type: string | null;
  object_id: string | null;
  project_id: string | null;
  result: string;
  ip: string | null;
  details: Record<string, unknown> | null;
}

export interface AuditFilters {
  action?: string;
  user?: string;
  project?: string;
  result?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

// --- Окна обслуживания (задача 2.1) ---

export type WindowKind = "once" | "recurring" | "blackout";

export interface Occurrence {
  window_id: number;
  window_name: string;
  kind: WindowKind;
  start: string;
  end: string;
  cancelled: boolean;
  blackouts: { id: number; name: string }[];
  /** Хосты, закрытые блэкаутом; null — закрыт весь проект. */
  blocked_hosts: string[] | null;
}

export interface CalendarItem extends Occurrence {
  tickets?: number;
  will_close?: number;
}

export interface WindowIn {
  name: string;
  kind: WindowKind;
  timezone: string;
  starts_at: string | null;
  ends_at: string | null;
  weekdays: number[];
  start_time: string;
  duration_minutes: number;
  valid_from: string | null;
  valid_until: string | null;
  hosts: string[];
  groups: string[];
  note: string;
  is_active: boolean;
}

export interface WindowOut extends WindowIn {
  id: number;
  project_id: string;
  kind_label: string;
  schedule: string;
  next: Occurrence | null;
  past: boolean;
  tickets: number;
  created_at: string;
  updated_at: string;
}

export interface PlanItem {
  ticket_id: number;
  title: string;
  kind: string;
  severity: Severity;
  status: TicketStatus;
  assignee: string | null;
  reboot: boolean;
  hosts: string[];
  skipped_hosts: { host: string; reason: string }[];
  vulns: number;
  estimate_minutes: number;
  start: string | null;
  end: string | null;
  fits: boolean;
}

export interface WindowPlan {
  occurrence: Occurrence;
  items: PlanItem[];
  will_close: number;
  will_close_by_severity: SevCounts;
  hosts: number;
  reboots: number;
  overflow_vulns: number;
  overflow_tickets: number;
  planned_minutes: number;
  window_minutes: number;
}

export interface WindowPlanOut {
  window: WindowOut;
  plan: WindowPlan | null;
  prev: string | null;
  next: string | null;
}

// --- Активы и правила назначения (задача 2.2) ---

export type Criticality = "critical" | "high" | "medium" | "low";

export interface AssetBrief {
  id: number;
  hostname: string;
  owner: string;
  criticality: Criticality;
  tags: string[];
  groups: string[];
}

export interface AssetOut extends AssetBrief {
  address: string;
  os_family: string;
  os_guess: string;
  engagement_id: number;
  scanner_asset_id: number;
  open_tickets: number;
  synced_at: string;
}

export interface AssetFacets {
  total: number;
  synced_at: string | null;
  groups: { name: string; assets: number; open_tickets: number }[];
  tags: { name: string; assets: number }[];
  owners: { name: string; assets: number }[];
  criticality: Record<Criticality, number>;
}

export interface AssetQuery {
  group?: string;
  tag?: string;
  owner?: string;
  criticality?: Criticality;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface AssetSyncOut {
  assets: number;
  created: number;
  updated: number;
  removed: number;
  groups: number;
  groups_removed: number;
  errors: { link_id: number; engagement_id: number; error: string }[];
}

export type HostMatch = "all" | "any";

export interface RuleIn {
  name: string;
  is_active: boolean;
  groups: string[];
  tags: string[];
  owners: string[];
  os: string[];
  kinds: string[];
  host_match: HostMatch;
  assignee_id: number | null;
  team_id: number | null;
}

export interface RuleOut extends Omit<RuleIn, "assignee_id" | "team_id"> {
  id: number;
  project_id: string;
  position: number;
  assignee: { id: number; display_name: string; available: boolean } | null;
  team: { id: number; name: string; members: number } | null;
  created_at: string;
  updated_at: string;
}

export interface TeamMemberOut {
  id: number;
  username: string;
  display_name: string;
  available: boolean;
}

export interface TeamOut {
  id: number;
  name: string;
  members: TeamMemberOut[];
  rules: number;
  created_at: string;
}

export interface RuleDecision {
  ticket_id: number;
  title: string;
  severity: Severity;
  kind: string;
  os: string;
  rule: { id: number; name: string } | null;
  assignee: { id: number; display_name: string } | null;
  note: string;
}

export interface RulesApplyOut {
  dry_run: boolean;
  tickets: number;
  assigned: number;
  items: RuleDecision[];
}

// ---------- SSH-учётки и ключи хостов (задача 2.3) ----------

export type SshAuth = "password" | "key";
export type SshBecome = "sudo" | "none";
export type SshCheckResult =
  | "ok"
  | "unreachable"
  | "timeout"
  | "auth_failed"
  | "host_key_mismatch"
  | "become_failed"
  | "error";

export interface SshCredentialIn {
  name: string;
  username: string;
  auth: SshAuth;
  port: number;
  become: SshBecome;
  /** Секреты только отправляются; пустая строка при правке — «не менять». */
  password?: string;
  private_key?: string;
  passphrase?: string;
  become_password?: string;
  clear_become_password?: boolean;
  hosts: string[];
  groups: string[];
  is_active: boolean;
  note: string;
}

export interface SshCredentialOut {
  id: number;
  project_id: string;
  name: string;
  username: string;
  auth: SshAuth;
  port: number;
  become: SshBecome;
  key_type: string;
  key_fingerprint: string;
  has_secret: boolean;
  has_become_password: boolean;
  hosts: string[];
  groups: string[];
  is_active: boolean;
  note: string;
  last_check: { at: string; host: string; result: SshCheckResult; label: string; message: string } | null;
  created_at: string;
  updated_at: string;
}

export interface HostKeyOut {
  id: number;
  host: string;
  port: number;
  key_type: string;
  fingerprint: string;
  status: "pinned" | "mismatch";
  pinned_via: "tofu" | "accepted";
  pinned_by: string | null;
  pinned_at: string;
  last_seen_at: string | null;
  mismatch: { key_type: string; fingerprint: string; at: string; count: number } | null;
}

export interface SshHostOut {
  host: string;
  hostname: string;
  groups: string[];
  in_project: boolean;
  credential: { id: number; name: string; username: string; port: number; why: "host" | "group" | "subnet" | "all"; detail: string } | null;
  keys: HostKeyOut[];
}

export interface SshCheckOut {
  result: SshCheckResult;
  label: string;
  message: string;
  ok: boolean;
  facts: { user?: string; uid?: number; os?: string; become?: "root" | "sudo" | "none" | "failed" };
  key_state: "new" | "pinned" | "mismatch";
  host_key: HostKeyOut | null;
}

// --- Раскатки (задача 2.4) ---

export type RolloutTemplate = "package" | "kernel" | "service" | "custom";
export type RolloutStatus =
  | "draft"
  | "dry_run"
  | "pending_approval"
  | "approved"
  | "running"
  | "done"
  | "failed"
  | "stopped"
  | "rejected"
  | "cancelled";
export type RolloutHostStatus =
  | "pending"
  | "dry_ok"
  | "dry_failed"
  | "queued"
  | "running"
  | "succeeded"
  | "reboot_pending"
  | "failed"
  | "skipped";
export type StageState = "pending" | "running" | "done" | "failed" | "skipped";

export interface TicketRolloutBrief {
  id: number;
  title: string;
  status: RolloutStatus;
  status_label: string;
  hosts: number;
  created_at: string;
  finished_at: string | null;
}

export interface RolloutCan {
  dry_run: boolean;
  approve: boolean;
  reject: boolean;
  start: boolean;
  stop: boolean;
  cancel: boolean;
}

export interface RolloutPlanItem {
  package: string;
  from: string;
  to: string;
}

export interface RolloutHostOut {
  id: number;
  host: string;
  stage: number | null;
  status: RolloutHostStatus;
  status_label: string;
  reason: string;
  credential: { id: number | null; name: string } | null;
  dry_status: "" | "ok" | "failed";
  dry_plan: RolloutPlanItem[];
  dry_note: string;
  versions_before: Record<string, string | null>;
  versions_after: Record<string, string | null>;
  rollback: string[];
  reboot_required: boolean;
  rebooted: boolean;
  kernel_before: string;
  kernel_after: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  canary: boolean;
}

export interface RolloutStage {
  key: "dry_run" | "approval" | "canary" | "batches" | "verify";
  label: string;
  state: StageState;
  hosts?: string[];
  batches?: { stage: number; hosts: string[]; state: StageState }[];
}

export interface RolloutOut {
  id: number;
  project_id: string;
  ticket: { id: number; title: string; status: TicketStatus; os: string } | null;
  title: string;
  template: RolloutTemplate;
  template_label: string;
  manager: string;
  packages: string[];
  fixed_version: string;
  service: string;
  command: string;
  window: { id: number; name: string } | null;
  canary_host: string;
  batch_percent: number;
  failure_threshold: number;
  status: RolloutStatus;
  status_label: string;
  error: string;
  note: string;
  prepared_by: UserRef | null;
  dry_run_at: string | null;
  dry_run_by: UserRef | null;
  decided_by: UserRef | null;
  decided_at: string | null;
  decision_note: string;
  allow_reboot: boolean;
  outside_window: boolean;
  outside_window_reason: string;
  custom_approved: boolean;
  started_by: UserRef | null;
  started_at: string | null;
  finished_at: string | null;
  stop_requested: boolean;
  stopped_by: UserRef | null;
  stop_reason: string;
  verification_ids: number[];
  counts: Partial<Record<RolloutHostStatus, number>>;
  hosts_total: number;
  created_at: string;
  updated_at: string;
  can?: RolloutCan;
  hosts?: RolloutHostOut[];
  stages?: RolloutStage[];
  step_counts?: Record<string, number>;
  verifications?: VerificationOut[];
}

export interface RolloutStepOut {
  id: number;
  host_id: number;
  phase: "dry_run" | "execute";
  label: string;
  command: string;
  returncode: number | null;
  ok: boolean;
  stdout: string;
  stderr: string;
  duration_ms: number;
  at: string;
}

export interface RolloutDraft {
  template: RolloutTemplate;
  manager: string;
  packages: string[];
  fixed_version: string;
  service: string;
  hosts: string[];
  canary_host: string;
  window_id: number | null;
  batch_percent: number;
  failure_threshold: number;
  reboot: boolean;
  windows: { id: number; name: string }[];
  active_rollout_id: number | null;
  can_prepare: boolean;
  can_custom: boolean;
  problems: string[];
}

export interface RolloutIn {
  template: RolloutTemplate;
  manager?: string;
  packages?: string[];
  fixed_version?: string;
  service?: string;
  command?: string;
  hosts?: string[];
  canary_host?: string;
  window_id?: number | null;
  batch_percent?: number;
  failure_threshold?: number;
  note?: string;
}

export interface RolloutMeta {
  templates: { id: RolloutTemplate; label: string }[];
  managers: { id: string; label: string }[];
  statuses: { id: RolloutStatus; label: string }[];
  host_statuses: { id: RolloutHostStatus; label: string }[];
  name_pattern: string;
}

// --- исключения (задача 2.5) ---
export type ExceptionKind = "risk_accepted" | "false_positive";
export type ExceptionStatus = "pending" | "active" | "rejected" | "withdrawn" | "revoked" | "expired";
export type ExceptionState = "all" | "pending" | "to_approve" | "active" | "review_soon" | "ended";

export interface ExceptionSync {
  action?: "mark" | "unmark";
  state?: "queued" | "done" | "partial" | "failed" | "skipped";
  at?: string;
  done?: number;
  failed?: number;
  skipped?: number;
  total?: number;
  marked?: string[];
  errors?: { host: string; vuln: string; error: string }[];
  note?: string;
}

export interface ExceptionExtension {
  at: string;
  by: number;
  by_name: string;
  from: string;
  to: string;
  reason: string;
}

export interface ExceptionCan {
  approve: boolean;
  reject: boolean;
  withdraw: boolean;
  revoke: boolean;
  extend: boolean;
  sync: boolean;
}

export interface ExceptionOut {
  id: number;
  project_id: string;
  ticket: { id: number; title: string; status: TicketStatus; severity: Severity; os: string; kind: string } | null;
  kind: ExceptionKind;
  kind_label: string;
  status: ExceptionStatus;
  status_label: string;
  reason: string;
  measures: string;
  review_on: string | null;
  days_left: number | null;
  review_soon: boolean;
  requested_by: UserRef | null;
  requested_at: string;
  approver: UserRef | null;
  decided_by: UserRef | null;
  decided_at: string | null;
  decision_note: string;
  ended_by: UserRef | null;
  ended_at: string | null;
  end_reason: string;
  prev_status: string;
  hosts: string[];
  hosts_now: number;
  new_hosts: string[];
  vuln_count: number;
  extensions: ExceptionExtension[];
  sync_scanner: boolean;
  sync: ExceptionSync;
  created_at: string;
  updated_at: string;
  can?: ExceptionCan;
}

export interface ExceptionIn {
  kind: ExceptionKind;
  reason: string;
  measures?: string;
  approver_id: number | null;
  review_on: string | null;
  sync_scanner?: boolean;
}

export interface ExceptionMeta {
  approvers: UserRef[];
  sync_available: boolean;
  today: string;
  min_review_on: string;
  max_review_on: string;
  default_review_on: string;
  soon_days: number;
}

export type ExceptionCounts = Record<ExceptionState | ExceptionKind, number>;

/* --- Отчёт о ходе устранения (задача 3.1) --- */

export type ReportFormat = "html" | "pdf" | "docx" | "json";
export type ReportVariant = "full" | "brief";

export interface ReportQuery {
  from: string;
  to: string;
  variant: ReportVariant;
}

export interface ReportMove {
  start: number;
  appeared: number;
  regression: number;
  fixed: number;
  end: number;
}

export interface ReportTicket {
  id: number;
  title: string;
  kind: string;
  kind_label: string;
  os: string;
  severity: Severity;
  status: TicketStatus;
  status_label: string;
  assignee: string | null;
  is_regression: boolean;
  hosts: number;
  hosts_confirmed: number;
  hosts_unverified: number;
  open_vulns: number;
  fixed_vulns: number;
  closed_at: string | null;
  closed_local: string;
  evidence?: { scanner_run_id: number | null; run_name: string; kind: string; finished_at: string | null; url: string };
}

export interface ReportOut {
  context: {
    title: string;
    project: { id: string; name: string; client: string; contract_ref: string };
    period: { from: string; to: string; days: number; timezone: string; label: string };
    variant: ReportVariant;
    generated_at: string;
    author: string;
    deadlines: boolean;
    tickets_as_of_now: boolean;
  };
  totals: {
    vulns: ReportMove;
    tickets_total: number;
    tickets_open: number;
    tickets_verified: number;
    tickets_exceptions: number;
    hosts_unverified: number;
  };
  by_severity: (ReportMove & { severity: Severity; label: string })[];
  weeks: { start: string; opened: SevCounts; closed: SevCounts }[];
  runs: {
    id: number;
    scanner_run_id: number;
    name: string;
    kind: string;
    kind_label: string;
    finished_at: string | null;
    finished_local: string;
    url: string;
    appeared: number;
    regression: number;
    fixed: number;
  }[];
  assignees: {
    name: string;
    open: number;
    in_work: number;
    awaiting_check: number;
    verified: number;
    open_vulns: number;
    fixed_vulns: number;
    by_severity: SevCounts;
  }[];
  groups: (ReportMove & { name: string; hosts: number })[];
  top_hosts: { host: string; open: number; by_severity: SevCounts }[];
  verified: ReportTicket[];
  remaining: ReportTicket[];
  exceptions: {
    id: number;
    ticket_id: number;
    ticket_title: string;
    severity: Severity;
    kind: ExceptionKind;
    kind_label: string;
    reason: string;
    approver: string;
    review_on: string | null;
    review_local: string;
    vulns: number;
  }[];
  key_points: string[];
}
