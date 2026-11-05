import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search, ShieldOff } from "lucide-react";
import { api } from "../api/client";
import type { ExceptionKind, ExceptionOut, ExceptionState } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { ExceptionDetails, ExceptionPill, ReviewDate } from "../components/Exceptions";
import { Pager } from "../components/Pager";
import { Drawer, Empty, ErrorAlert, Kpi, Loading, SeverityBadge } from "../components/ui";
import { fmtDate, fmtNumber } from "../lib/format";
import { EXCEPTION_KIND_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

const PAGE = 25;
const TABS: { id: ExceptionState; label: string }[] = [
  { id: "pending", label: "Ждут утверждения" },
  { id: "active", label: "Действуют" },
  { id: "review_soon", label: "Скоро пересмотр" },
  { id: "ended", label: "Завершённые" },
  { id: "all", label: "Все" },
];

const EMPTY: Record<ExceptionState, string> = {
  pending: "Нет исключений, ждущих утверждения",
  to_approve: "Вам нечего утверждать",
  active: "Действующих исключений нет",
  review_soon: "В ближайшие две недели пересматривать нечего",
  ended: "Завершённых исключений нет",
  all: "Исключений пока нет",
};

export function ExceptionsPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const [params, setParams] = useSearchParams();
  const state = (TABS.find((t) => t.id === params.get("state"))?.id ?? (params.get("state") === "to_approve" ? "to_approve" : "pending")) as ExceptionState;
  const kind = (params.get("kind") as ExceptionKind | null) ?? undefined;
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [q, setQ] = useState(params.get("q") ?? "");
  const query = params.get("q") ?? "";
  const counts = useAsync(() => api.exceptionCounts(projectId), [projectId]);
  const list = useAsync(
    () => api.exceptions(projectId, { state, kind, q: query || undefined, limit: PAGE, offset }),
    [projectId, state, kind, query, offset],
  );
  const openId = Number(params.get("id") ?? 0) || null;
  const opened = useAsync(() => api.exception(openId!), [openId], openId !== null);

  const set = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "") p.delete(k);
      else p.set(k, v);
    }
    if (!("offset" in patch)) p.delete("offset");
    setParams(p);
  };
  const reload = () => {
    void list.reload();
    void counts.reload();
    if (openId) void opened.reload();
  };
  const c = counts.data;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Исключения</h1>
        </div>
      </div>
      {c && (
        <div className="kpis">
          <Kpi label="Ждут утверждения" value={fmtNumber(c.pending)} delta={has("exception_approve") ? `у вас — ${fmtNumber(c.to_approve)}` : undefined} tone={c.to_approve > 0 ? "warn" : undefined} />
          <Kpi label="Принят риск" value={fmtNumber(c.risk_accepted)} delta="действуют" />
          <Kpi label="Ложные срабатывания" value={fmtNumber(c.false_positive)} delta="действуют" />
          <Kpi label="Пересмотр в 14 дней" value={fmtNumber(c.review_soon)} tone={c.review_soon > 0 ? "warn" : undefined} delta="иначе заявка вернётся в работу" />
        </div>
      )}
      <section className="card">
        <div className="filters">
          <div className="seg" role="radiogroup" aria-label="Какие исключения показать">
            {TABS.map((t) => (
              <button key={t.id} type="button" role="radio" aria-checked={t.id === state} onClick={() => set({ state: t.id === "pending" ? null : t.id })}>
                {t.label}
                {c && t.id !== "all" && c[t.id] > 0 && <span className="count" style={{ marginLeft: 6 }}>{c[t.id]}</span>}
              </button>
            ))}
          </div>
          <select className="select" style={{ width: "auto" }} aria-label="Вид исключения" value={kind ?? ""} onChange={(e) => set({ kind: e.target.value || null })}>
            <option value="">Все виды</option>
            {(Object.keys(EXCEPTION_KIND_LABEL) as ExceptionKind[]).map((k) => (
              <option key={k} value={k}>
                {EXCEPTION_KIND_LABEL[k]}
              </option>
            ))}
          </select>
          <form
            className="search"
            role="search"
            onSubmit={(e) => {
              e.preventDefault();
              set({ q: q.trim() || null });
            }}
          >
            <Search size={15} aria-hidden="true" />
            <input className="input" placeholder="№ заявки, название или обоснование" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Поиск" />
          </form>
          {list.data && <span className="count">{fmtNumber(list.data.total)}</span>}
        </div>
        {list.error && <ErrorAlert error={list.error} onRetry={() => void list.reload()} />}
        {list.loading && !list.data && <Loading />}
        {list.data && list.data.items.length === 0 && (
          <Empty title={query || kind ? "Ничего не найдено" : EMPTY[state]} icon={<ShieldOff size={28} />}>
            Исключение оформляется из карточки заявки кнопкой «Исключение»: обоснование, утверждающий и дата пересмотра. Утверждает второй руководитель.
          </Empty>
        )}
        {list.data && list.data.items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Заявка</th>
                  <th>Вид</th>
                  <th>Обоснование</th>
                  <th>Статус</th>
                  <th>Утверждающий</th>
                  <th>Пересмотр</th>
                  <th className="right">Оформлено</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((ex: ExceptionOut) => (
                  <tr key={ex.id} className="row-click" onClick={() => set({ id: String(ex.id), offset: String(offset) })}>
                    <td style={{ minWidth: 220 }}>
                      {ex.ticket && (
                        <>
                          <Link to={`/tickets/${ex.ticket.id}?project=${projectId}`} onClick={(e) => e.stopPropagation()}>
                            №{ex.ticket.id} {ex.ticket.title}
                          </Link>
                          <div className="inline faint" style={{ gap: 6, marginTop: 2 }}>
                            <SeverityBadge severity={ex.ticket.severity} short />
                            {ex.ticket.os && <span>{ex.ticket.os}</span>}
                          </div>
                        </>
                      )}
                    </td>
                    <td className="nowrap">{ex.kind_label}</td>
                    <td style={{ minWidth: 200, maxWidth: 360 }}>
                      <span className="clamp-2">{ex.reason}</span>
                    </td>
                    <td className="nowrap">
                      <ExceptionPill ex={ex} />
                      {ex.kind === "false_positive" && ex.sync.state === "failed" && (
                        <div className="faint" style={{ fontSize: 12, color: "var(--danger)" }}>
                          «Сканер»: ошибка
                        </div>
                      )}
                    </td>
                    <td className="nowrap">
                      {ex.approver?.display_name ?? "—"}
                      {ex.can?.approve && (
                        <div className="faint" style={{ fontSize: 12, color: "var(--warn)" }}>
                          ждёт вашего решения
                        </div>
                      )}
                    </td>
                    <td>
                      <ReviewDate ex={ex} />
                    </td>
                    <td className="right nowrap faint">
                      {fmtDate(ex.requested_at)}
                      <div>{ex.requested_by?.display_name}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && list.data.total > PAGE && (
          <Pager total={list.data.total} limit={PAGE} offset={offset} onChange={(o) => set({ offset: String(o) })} />
        )}
      </section>
      {openId && (
        <Drawer
          title={opened.data ? `Исключение №${opened.data.id}` : "Исключение"}
          onClose={() => set({ id: null, offset: offset ? String(offset) : null })}
        >
          {opened.error && <ErrorAlert error={opened.error} />}
          {opened.loading && !opened.data && <Loading />}
          {opened.data && <ExceptionDetails ex={opened.data} onChanged={reload} showTicket />}
        </Drawer>
      )}
    </>
  );
}
