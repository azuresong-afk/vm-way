import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRightLeft, ClipboardList, Search, UserPlus, X } from "lucide-react";
import { api } from "../api/client";
import type { BulkOut, Severity, TicketQuery, TicketStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { Pager } from "../components/Pager";
import { AssigneeSelect } from "../components/TicketActions";
import { TicketDrawer } from "../components/TicketDrawer";
import { TicketsTable } from "../components/TicketsTable";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtNumber, plural } from "../lib/format";
import { KIND_LABEL, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, STATUS_ORDER, reasonRequired } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

type SortKey = NonNullable<TicketQuery["sort"]>;
const SORTS: SortKey[] = ["priority", "severity", "created", "updated", "title", "hosts"];

/** Фильтры живут в адресе: ссылки со «Сводки» и из других продуктов открывают нужный срез. */
function useFilters() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const list = (k: string) => params.getAll(k).filter(Boolean);
  const statusParam = get("status");
  const stateParam = get("state");
  const scope = statusParam || stateParam || "open";
  const sortParam = get("sort") as SortKey;
  const f = {
    scope,
    severity: list("severity") as Severity[],
    kind: list("kind"),
    os: get("os"),
    assignee: get("assignee"),
    host: get("host"),
    q: get("q"),
    sort: SORTS.includes(sortParam) ? sortParam : ("priority" as SortKey),
    order: (get("order") === "desc" ? "desc" : "asc") as "asc" | "desc",
    offset: Math.max(0, Number(get("offset")) || 0),
    limit: [25, 50, 100, 200].includes(Number(get("limit"))) ? Number(get("limit")) : 50,
  };
  const set = useCallback(
    (patch: Record<string, string | string[] | number | null>, keepOffset = false) => {
      const next = new URLSearchParams(params);
      for (const [k, v] of Object.entries(patch)) {
        next.delete(k);
        if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
        else if (v !== null && v !== "" && v !== undefined) next.set(k, String(v));
      }
      if (!keepOffset) next.delete("offset");
      setParams(next, { replace: true });
    },
    [params, setParams],
  );
  const query: TicketQuery = {
    state: f.scope === "open" || f.scope === "closed" ? f.scope : undefined,
    status: f.scope !== "open" && f.scope !== "closed" && f.scope !== "all" ? [f.scope as TicketStatus] : undefined,
    severity: f.severity.length ? f.severity : undefined,
    kind: f.kind.length ? f.kind : undefined,
    os: f.os ? [f.os] : undefined,
    assignee: f.assignee || undefined,
    host: f.host || undefined,
    q: f.q || undefined,
    sort: f.sort,
    order: f.order,
    limit: f.limit,
    offset: f.offset,
  };
  return { f, set, query };
}

function BulkModal({
  projectId,
  ids,
  mode,
  onClose,
  onDone,
}: {
  projectId: string;
  ids: number[];
  mode: "assign" | "status";
  onClose: () => void;
  onDone: (r: BulkOut) => void;
}) {
  const [who, setWho] = useState<number | null>(null);
  const [status, setStatus] = useState<TicketStatus>("in_progress");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Причина обязательна для исключений и возврата из «Исправлено» — спросим всегда, если цель того требует.
  const need = mode === "status" && reasonRequired("assigned", status);
  const targets: TicketStatus[] = ["in_progress", "waiting_window", "fixed", "risk_accepted", "false_positive"];
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const r =
        mode === "assign"
          ? await api.bulk(projectId, { ticket_ids: ids, action: "assign", assignee_id: who })
          : await api.bulk(projectId, { ticket_ids: ids, action: "status", status, reason: reason.trim() || undefined });
      onDone(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const n = `${fmtNumber(ids.length)} ${plural(ids.length, ["заявку", "заявки", "заявок"])}`;
  return (
    <Modal
      title={mode === "assign" ? `Назначить ${n}` : `Перевести ${n}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={submit}
            disabled={busy || (need && !reason.trim())}
          >
            {busy ? "Применение…" : "Применить"}
          </button>
        </>
      }
    >
      {mode === "assign" ? (
        <label className="field">
          <span>Исполнитель</span>
          <AssigneeSelect projectId={projectId} value={who} onChange={setWho} />
          <small>Закрытые заявки не меняются; по каждой отказанной заявке будет указана причина.</small>
        </label>
      ) : (
        <>
          <label className="field">
            <span>Новый статус</span>
            <select className="select" value={status} onChange={(e) => setStatus(e.target.value as TicketStatus)}>
              {targets.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABEL[s]}
                </option>
              ))}
            </select>
            <small>Каждая заявка проверяется по правилам переходов: подходящие изменятся, по остальным будет причина отказа.</small>
          </label>
          <label className="field">
            <span>Причина{need ? "" : " (необязательно)"}</span>
            <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 89 }} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
            {status === "in_progress" && <small>Для заявок из «Исправлено, ждёт проверки» возврат в работу требует причины.</small>}
          </label>
        </>
      )}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

export function TicketsPage({ mine }: { mine?: boolean }) {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const { f, set, query } = useFilters();
  const effective = mine ? { ...query, assignee: "me" } : query;
  const key = JSON.stringify(effective);
  const page = useAsync(() => api.tickets(projectId, effective), [projectId, key]);
  const facets = useAsync(() => api.ticketFacets(projectId), [projectId]);
  const [open, setOpen] = useState<number | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulk, setBulk] = useState<"assign" | "status" | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkOut | null>(null);
  const [text, setText] = useState(f.q);
  const canBulk = has("ticket_assign") && !mine;

  useEffect(() => setText(f.q), [f.q]);
  useEffect(() => setSelected(new Set()), [projectId]);
  // Поиск — с задержкой, чтобы не дёргать API на каждую букву.
  useEffect(() => {
    if (text === f.q) return;
    const t = window.setTimeout(() => set({ q: text.trim() }), 300);
    return () => window.clearTimeout(t);
  }, [text, f.q, set]);

  const setScope = (v: string) =>
    set(
      v === "open"
        ? { status: null, state: null }
        : v === "closed" || v === "all"
          ? { status: null, state: v }
          : { status: v, state: null },
    );
  const onSort = (k: SortKey) => set({ sort: k, order: f.sort === k && f.order === "asc" ? "desc" : "asc" }, true);
  const onSelect = (ids: number[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      ids.forEach((id) => (on ? next.add(id) : next.delete(id)));
      return next;
    });
  const toggle = (k: "severity" | "kind", v: string) => {
    const cur = f[k] as string[];
    set({ [k]: cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v] });
  };
  const hasFilters = f.severity.length || f.kind.length || f.os || f.assignee || f.host || f.q || f.scope !== "open";
  const total = page.data?.total ?? 0;
  const ids = useMemo(() => [...selected], [selected]);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>{mine ? "Мои задачи" : "Заявки"}</h1>
        </div>
        {canBulk && selected.size > 0 && (
          <div className="actions">
            <span className="muted">
              Выбрано {fmtNumber(selected.size)} {plural(selected.size, ["заявка", "заявки", "заявок"])}
            </span>
            <button type="button" className="btn" onClick={() => setBulk("assign")}>
              <UserPlus size={15} aria-hidden="true" /> Назначить
            </button>
            <button type="button" className="btn" onClick={() => setBulk("status")}>
              <ArrowRightLeft size={15} aria-hidden="true" /> Перевести
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setSelected(new Set())}>
              Снять выбор
            </button>
          </div>
        )}
      </div>

      {bulkResult && (
        <div className={`alert ${bulkResult.failed.length ? "alert-warn" : "alert-ok"}`} role="status">
          <span style={{ flex: 1 }}>
            Изменено: {fmtNumber(bulkResult.changed.length)}
            {bulkResult.unchanged.length > 0 && `, без изменений: ${fmtNumber(bulkResult.unchanged.length)}`}
            {bulkResult.failed.length > 0 && (
              <>
                , отказ: {fmtNumber(bulkResult.failed.length)}
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {bulkResult.failed.slice(0, 8).map((x) => (
                    <li key={x.id}>
                      №{x.id}: {x.error}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </span>
          <button type="button" className="btn btn-sm btn-ghost icon-btn" aria-label="Скрыть" onClick={() => setBulkResult(null)}>
            <X size={15} />
          </button>
        </div>
      )}

      <section className="card">
        <div className="filters">
          <label className="search filters-q">
            <Search size={15} aria-hidden="true" />
            <input
              className="input"
              type="search"
              placeholder="№, название, CVE, хост"
              aria-label="Поиск заявок"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          </label>
          <select className="select" aria-label="Статус" value={f.scope} onChange={(e) => setScope(e.target.value)}>
            <option value="open">Открытые</option>
            <option value="closed">Закрытые</option>
            <option value="all">Все статусы</option>
            {STATUS_ORDER.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
          {!mine && (
            <select className="select" aria-label="Исполнитель" value={f.assignee} onChange={(e) => set({ assignee: e.target.value })}>
              <option value="">Все исполнители</option>
              {has("ticket_work") && <option value="me">Мои</option>}
              <option value="none">Без исполнителя</option>
            </select>
          )}
          {(facets.data?.os.length ?? 0) > 1 && (
            <select className="select" aria-label="ОС" value={f.os} onChange={(e) => set({ os: e.target.value })}>
              <option value="">Все ОС</option>
              {facets.data!.os.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.id} · {o.open}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="filters filters-chips">
          <span className="faint chip-row-label">Уровень</span>
          {SEVERITIES.slice(0, 4).map((s) => (
            <button key={s} type="button" className="chip" aria-pressed={f.severity.includes(s)} onClick={() => toggle("severity", s)}>
              <span className={`sev sev-${s}`}>
                <i aria-hidden="true" />
              </span>
              {SEVERITY_LABEL[s]}
            </button>
          ))}
          {(facets.data?.kinds.length ?? 0) > 1 && (
            <>
              <span className="faint chip-row-label" style={{ marginLeft: 8 }}>
                Вид
              </span>
              {facets.data!.kinds.map((k) => (
                <button key={k.id} type="button" className="chip" aria-pressed={f.kind.includes(k.id)} onClick={() => toggle("kind", k.id)}>
                  {KIND_LABEL[k.id] ?? k.id}
                </button>
              ))}
            </>
          )}
          {f.host && (
            <button type="button" className="chip" aria-pressed="true" onClick={() => set({ host: null })} aria-label={`Снять фильтр по хосту ${f.host}`}>
              хост <span className="mono">{f.host}</span> <X size={13} aria-hidden="true" />
            </button>
          )}
          {hasFilters ? (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => set({ severity: [], kind: [], os: null, assignee: null, host: null, q: null, status: null, state: null })}>
              Сбросить
            </button>
          ) : null}
        </div>
        {page.error && (
          <div style={{ padding: "0 20px 20px" }}>
            <ErrorAlert error={page.error} onRetry={() => void page.reload()} />
          </div>
        )}
        {page.loading && !page.data && <Loading />}
        {page.data && page.data.items.length === 0 && (
          <Empty title={hasFilters ? "Ничего не найдено" : mine ? "На вас нет открытых заявок" : "Заявок нет"} icon={<ClipboardList size={28} />}>
            {hasFilters
              ? "Измените фильтры или сбросьте их."
              : mine
                ? "Свободные заявки можно взять в работу на этой странице ниже или в разделе «Заявки»."
                : "Заявки появятся после импорта прогона «Сканера»."}
          </Empty>
        )}
        {page.data && page.data.items.length > 0 && (
          <>
            <TicketsTable
              items={page.data.items}
              sort={f.sort}
              order={f.order}
              onSort={onSort}
              onOpen={(t) => setOpen(t.id)}
              selected={canBulk ? selected : undefined}
              onSelect={canBulk ? onSelect : undefined}
              activeId={open}
            />
            <Pager
              total={total}
              offset={f.offset}
              limit={f.limit}
              onChange={(o) => set({ offset: o }, true)}
              onLimit={(l) => set({ limit: l })}
              label="Страницы заявок"
            />
          </>
        )}
      </section>

      {open !== null && <TicketDrawer id={open} onClose={() => setOpen(null)} onChanged={() => void page.reload()} />}
      {bulk && (
        <BulkModal
          projectId={projectId}
          ids={ids}
          mode={bulk}
          onClose={() => setBulk(null)}
          onDone={(r) => {
            setBulk(null);
            setBulkResult(r);
            setSelected(new Set());
            void page.reload();
          }}
        />
      )}
    </>
  );
}
