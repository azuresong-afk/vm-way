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
  host?: string;
  q?: string;
  sort?: "priority" | "severity" | "created" | "updated" | "title" | "hosts";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface TicketFacets {
  os: { id: string; total: number; open: number }[];
  kinds: { id: string; total: number; open: number }[];
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
