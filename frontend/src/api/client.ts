// Тонкий клиент REST API «Устранения»: Bearer-токен, разбор ошибок FastAPI.

import type {
  AssetFacets,
  AssetOut,
  AssetQuery,
  AssetSyncOut,
  AssignableUser,
  AuditFilters,
  AuditOut,
  BulkOut,
  CommentOut,
  EngagementOut,
  JobOut,
  LinkOut,
  MeOut,
  Page,
  ProjectIn,
  ProjectOut,
  RolesOut,
  RuleIn,
  RuleOut,
  RulesApplyOut,
  RunOut,
  SearchOut,
  Severity,
  SourceIn,
  SourceOut,
  SourceTestOut,
  SummaryOut,
  TeamOut,
  TicketBrief,
  TicketDetail,
  TicketFacets,
  TicketHistoryOut,
  TicketMeta,
  TicketQuery,
  TicketStatus,
  TokenOut,
  UserCreate,
  UserOut,
  UserPatch,
  VerificationOut,
  VulnOut,
  CalendarItem,
  WindowIn,
  WindowOut,
  WindowPlanOut,
} from "./types";

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

/** Ключ общий для всех продуктов на одном origin (контракт платформы, п. 2). */
export const TOKEN_KEY = "platform.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let token: string | null = readToken();
let onUnauthorized: (() => void) | null = null;

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return token;
}

export function setToken(value: string | null): void {
  token = value;
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* хранилище недоступно — токен живёт до перезагрузки вкладки */
  }
}

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

/** Человекочитаемый текст из ответа FastAPI ({detail: str | [{msg}] | {message}}). */
export function errorText(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : String(d)))
      .join("; ");
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  return fallback;
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError(0, "Сервер API недоступен");
  }
  if (res.ok) return res;
  let detail: unknown;
  try {
    detail = (await res.json()).detail;
  } catch {
    detail = undefined;
  }
  if (res.status === 401 && token) {
    setToken(null);
    onUnauthorized?.();
  }
  throw new ApiError(res.status, errorText(detail, `Ошибка ${res.status}`), detail);
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await request(path, init);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Страница списка: тело — элементы, общее число — заголовок X-Total-Count. */
async function page<T>(path: string, init?: RequestInit): Promise<Page<T>> {
  const res = await request(path, init);
  const items = (await res.json()) as T[];
  const total = Number(res.headers.get("X-Total-Count") ?? items.length);
  return { items, total: Number.isFinite(total) ? total : items.length };
}

/** Query-строка для списков: массивы — повтором параметра, пустое опускается. */
export function listQuery(params: object): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (Array.isArray(v)) for (const x of v) q.append(k, String(x));
    else if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  return qs ? `?${qs}` : "";
}

const body = (data: unknown): RequestInit => ({ body: JSON.stringify(data) });
const post = (data?: unknown): RequestInit => ({ method: "POST", ...(data === undefined ? {} : body(data)) });
const enc = encodeURIComponent;

export const api = {
  login: (username: string, password: string) => json<TokenOut>("/auth/token", post({ username, password })),
  logout: () => json<{ ok: boolean }>("/auth/logout", post()),
  me: () => json<MeOut>("/me"),

  projects: (includeArchived = false) =>
    json<ProjectOut[]>(`/projects${listQuery({ include_archived: includeArchived || undefined, limit: 500 })}`),
  createProject: (data: ProjectIn) => json<ProjectOut>("/projects", post(data)),
  updateProject: (id: string, data: Partial<ProjectIn>) =>
    json<ProjectOut>(`/projects/${enc(id)}`, { method: "PATCH", ...body(data) }),

  summary: (projectId: string, period: "3m" | "1y") =>
    json<SummaryOut>(`/projects/${enc(projectId)}/summary?period=${period}`),
  search: (q: string, projectId: string | null, init?: RequestInit) =>
    json<SearchOut>(`/search${listQuery({ q, project: projectId, limit: 6 })}`, init),

  ticketMeta: () => json<TicketMeta>("/ticket-meta"),
  ticketFacets: (projectId: string) => json<TicketFacets>(`/projects/${enc(projectId)}/ticket-facets`),
  tickets: (projectId: string, query: TicketQuery) =>
    page<TicketBrief>(`/projects/${enc(projectId)}/tickets${listQuery(query)}`),
  ticket: (id: number) => json<TicketDetail>(`/tickets/${id}`),
  ticketHistory: (id: number) => json<TicketHistoryOut>(`/tickets/${id}/history`),
  take: (id: number) => json<TicketBrief>(`/tickets/${id}/take`, post()),
  assign: (id: number, assigneeId: number | null) =>
    json<TicketBrief>(`/tickets/${id}/assign`, post({ assignee_id: assigneeId })),
  setStatus: (id: number, status: TicketStatus, reason?: string) =>
    json<TicketBrief>(`/tickets/${id}/status`, post({ status, reason: reason || null })),
  override: (id: number, data: { severity: Severity | null; priority: string | null; reason: string }) =>
    json<TicketBrief>(`/tickets/${id}/override`, post(data)),
  comment: (id: number, text: string) => json<CommentOut>(`/tickets/${id}/comments`, post({ body: text })),
  watch: (id: number, watch: boolean) =>
    json<{ ticket_id: number; watching: boolean }>(`/tickets/${id}/watch`, post({ watch })),
  verify: (id: number, hosts?: string[], markFixed = true) =>
    json<{ ticket: TicketBrief; verifications: VerificationOut[] }>(
      `/tickets/${id}/verify`,
      post({ hosts: hosts?.length ? hosts : null, mark_fixed: markFixed }),
    ),
  bulk: (
    projectId: string,
    data: {
      ticket_ids: number[];
      action: "assign" | "status" | "window";
      assignee_id?: number | null;
      status?: TicketStatus;
      reason?: string;
      window_id?: number | null;
    },
  ) => json<BulkOut>(`/projects/${enc(projectId)}/tickets/bulk`, post(data)),
  placeInWindow: (id: number, windowId: number | null) =>
    json<TicketBrief>(`/tickets/${id}/window`, post({ window_id: windowId })),
  windows: (projectId: string) => json<WindowOut[]>(`/projects/${enc(projectId)}/windows`),
  createWindow: (projectId: string, data: WindowIn) => json<WindowOut>(`/projects/${enc(projectId)}/windows`, post(data)),
  updateWindow: (id: number, data: Partial<WindowIn>) =>
    json<WindowOut>(`/windows/${id}`, { method: "PATCH", ...body(data) }),
  deleteWindow: (id: number) => json<void>(`/windows/${id}`, { method: "DELETE" }),
  windowPlan: (id: number, at?: string) => json<WindowPlanOut>(`/windows/${id}/plan${listQuery({ at })}`),
  calendar: (projectId: string, from?: string, to?: string) =>
    json<{ from: string; to: string; items: CalendarItem[] }>(
      `/projects/${enc(projectId)}/calendar${listQuery({ from, to })}`,
    ),
  assets: (projectId: string, query: AssetQuery) =>
    page<AssetOut>(`/projects/${enc(projectId)}/assets${listQuery(query)}`),
  assetFacets: (projectId: string) => json<AssetFacets>(`/projects/${enc(projectId)}/asset-facets`),
  syncAssets: (projectId: string) => json<AssetSyncOut>(`/projects/${enc(projectId)}/assets/sync`, post()),
  rules: (projectId: string) => json<RuleOut[]>(`/projects/${enc(projectId)}/rules`),
  createRule: (projectId: string, data: RuleIn) => json<RuleOut>(`/projects/${enc(projectId)}/rules`, post(data)),
  updateRule: (id: number, data: Partial<RuleIn>) => json<RuleOut>(`/rules/${id}`, { method: "PATCH", ...body(data) }),
  deleteRule: (id: number) => json<void>(`/rules/${id}`, { method: "DELETE" }),
  reorderRules: (projectId: string, ids: number[]) =>
    json<RuleOut[]>(`/projects/${enc(projectId)}/rules/order`, { method: "PUT", ...body({ ids }) }),
  applyRules: (projectId: string, dryRun: boolean) =>
    json<RulesApplyOut>(`/projects/${enc(projectId)}/rules/apply`, post({ dry_run: dryRun })),
  teams: () => json<TeamOut[]>("/teams"),
  createTeam: (data: { name: string; member_ids: number[] }) => json<TeamOut>("/teams", post(data)),
  updateTeam: (id: number, data: { name?: string; member_ids?: number[] }) =>
    json<TeamOut>(`/teams/${id}`, { method: "PATCH", ...body(data) }),
  deleteTeam: (id: number) => json<void>(`/teams/${id}`, { method: "DELETE" }),
  assignable: (projectId: string) => json<AssignableUser[]>(`/users/assignable?project_id=${enc(projectId)}`),
  vulnerabilities: (projectId: string, query: { ticket_id?: number; state?: string; limit?: number; offset?: number }) =>
    page<VulnOut>(`/projects/${enc(projectId)}/vulnerabilities${listQuery(query)}`),

  runs: (projectId: string, limit = 10) => page<RunOut>(`/projects/${enc(projectId)}/runs?limit=${limit}`),
  job: (id: number) => json<JobOut>(`/jobs/${id}`),
  importNew: (projectId: string) => json<JobOut>(`/projects/${enc(projectId)}/import`, post({})),
  jobs: (projectId: string, active = true) =>
    page<JobOut>(`/projects/${enc(projectId)}/jobs${listQuery({ active: active || undefined, limit: 10 })}`),

  users: () => page<UserOut>("/users?limit=500"),
  roles: () => json<RolesOut>("/roles"),
  createUser: (data: UserCreate) => json<UserOut>("/users", post(data)),
  updateUser: (id: number, data: UserPatch) => json<UserOut>(`/users/${id}`, { method: "PATCH", ...body(data) }),
  setPassword: (id: number, password: string) => json<{ ok: boolean }>(`/users/${id}/password`, post({ password })),

  sources: () => json<SourceOut[]>("/sources"),
  createSource: (data: SourceIn) => json<SourceOut>("/sources", post(data)),
  updateSource: (id: number, data: Partial<SourceIn>) =>
    json<SourceOut>(`/sources/${id}`, { method: "PATCH", ...body(data) }),
  deleteSource: (id: number) => json<void>(`/sources/${id}`, { method: "DELETE" }),
  testSource: (id: number) => json<SourceTestOut>(`/sources/${id}/test`, post()),
  engagements: (sourceId: number) => json<EngagementOut[]>(`/sources/${sourceId}/engagements`),
  links: (projectId: string) => json<LinkOut[]>(`/projects/${enc(projectId)}/links`),
  createLink: (projectId: string, sourceId: number, engagementId: number) =>
    json<LinkOut>(`/projects/${enc(projectId)}/links`, post({ source_id: sourceId, engagement_id: engagementId })),
  deleteLink: (id: number) => json<void>(`/links/${id}`, { method: "DELETE" }),

  audit: (f: AuditFilters) => page<AuditOut>(`/audit${listQuery(f)}`),
  auditExport: async (f: AuditFilters): Promise<Blob> => {
    const res = await request(`/audit/export${listQuery({ ...f, limit: undefined, offset: undefined })}`);
    return res.blob();
  },
};
