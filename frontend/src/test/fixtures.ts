import type { MeOut, ProjectOut, TicketBrief, TicketDetail } from "../api/types";

export const project: ProjectOut = {
  id: "p1",
  name: "Демо",
  client: "АО «Порт»",
  contract_ref: "",
  period_from: null,
  period_to: null,
  status: "active",
  platform_project_id: null,
  created_at: "2026-11-01T10:00:00",
};

export function me(roles: string[], permissions: MeOut["permissions"]): MeOut {
  return { id: 7, username: "eng", display_name: "Смирнов Д. В.", roles, role_labels: [], permissions, projects: ["*"] };
}

export const engineer = me(["engineer"], ["view", "import", "ticket_work", "verify"]);
export const manager = me(["manager"], ["view", "import", "ticket_work", "ticket_assign", "ticket_override", "verify", "audit_view"]);

export const brief: TicketBrief = {
  id: 5,
  project_id: "p1",
  title: "Обновить glibc на РЕД ОС 7.3 до 2.35-9.el7",
  kind: "package",
  scanner_kind: "package",
  os: "РЕД ОС 7.3",
  os_family: "redos",
  severity: "high",
  scanner_severity: "high",
  severity_overridden: false,
  priority: { rank: 16, label: "high" },
  status: "new",
  status_label: "Новая",
  is_regression: false,
  assignee: null,
  reboot: false,
  hosts_total: 4,
  hosts_confirmed: 1,
  vulns_open: 3,
  vulns_total: 4,
  cves: ["CVE-2024-2961"],
  created_at: "2026-11-04T20:14:00",
  updated_at: "2026-11-04T20:14:00",
  closed_at: null,
};

export const detail: TicketDetail = {
  ...brief,
  fix_key: "k",
  action: {
    kind_label: "Обновление пакета",
    manager: "rpm",
    packages: ["glibc"],
    fixed_version: "2.35-9.el7",
    software: null,
    steps: ["Обновите пакет glibc"],
    commands: ["sudo yum update -y glibc"],
    verify: ["rpm -q glibc"],
    reboot: false,
    details: null,
    details_source: null,
    cves: ["CVE-2024-2961"],
    bdu_ids: ["BDU:2024-03128"],
    advisories: [],
    references: [],
    scanner_title: null,
  },
  override_reason: "",
  evidence: null,
  hosts: [
    { id: 1, host: "10.20.3.31", installed: "2.35-6.el7", note: "", status: "confirmed", reason: "", vulnerability_ids: [], last_check: null, updated_at: "" },
    { id: 2, host: "10.20.3.32", installed: "2.35-6.el7", note: "", status: "open", reason: "", vulnerability_ids: [], last_check: null, updated_at: "" },
  ],
  vulnerabilities: [],
  watchers: [],
  watching: false,
  verifications: [],
  can: { statuses: [], take: true, assign: false, override: false, comment: true, verify: true },
};
