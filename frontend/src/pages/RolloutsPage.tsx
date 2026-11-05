import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Rocket } from "lucide-react";
import { api } from "../api/client";
import type { RolloutOut, RolloutStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { Pager } from "../components/Pager";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { fmtDate, fmtNumber } from "../lib/format";
import { ROLLOUT_STATUS_PILL } from "../lib/labels";
import { useAsync, useInterval } from "../lib/useAsync";

const PAGE = 25;
const FILTERS: { id: string; label: string; status?: RolloutStatus[]; active?: boolean }[] = [
  { id: "active", label: "В работе", active: true },
  { id: "approval", label: "Ждут утверждения", status: ["pending_approval"] },
  { id: "all", label: "Все" },
];

function Progress({ r }: { r: RolloutOut }) {
  const c = r.counts;
  const ok = (c.succeeded ?? 0) + (c.reboot_pending ?? 0);
  const bad = c.failed ?? 0;
  if (!r.started_at) {
    const dry = c.dry_ok ?? 0;
    return <span className="faint">{r.dry_run_at ? `пробный прогон: ${dry} из ${r.hosts_total}` : `${r.hosts_total} хост(ов)`}</span>;
  }
  return (
    <span className="nowrap">
      {ok} из {r.hosts_total}
      {bad > 0 && <span style={{ color: "var(--danger)" }}> · ошибок {bad}</span>}
      {(c.reboot_pending ?? 0) > 0 && <span className="faint"> · ждут перезагрузки {c.reboot_pending}</span>}
    </span>
  );
}

/** Сколько хостов проекта раскатка обрабатывает одновременно — настраивает руководитель. */
function Parallelism({ projectId }: { projectId: string }) {
  const { has } = useAuth();
  const s = useAsync(() => api.rolloutSettings(projectId), [projectId]);
  const [error, setError] = useState<string | null>(null);
  if (!s.data) return null;
  const canEdit = has("rollout_approve");
  const save = async (v: number) => {
    setError(null);
    try {
      s.setData(await api.setRolloutSettings(projectId, v));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <label className="inline" style={{ gap: 8, fontSize: 13 }} title="Сколько хостов проекта раскатка обрабатывает одновременно; раскатки проекта идут по одной">
      <span className="faint">Хостов одновременно</span>
      {canEdit ? (
        <select className="select" style={{ width: 80 }} value={s.data.rollout_parallelism} onChange={(e) => void save(Number(e.target.value))}>
          {[1, 2, 3, 5, 10, 20, 50].map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      ) : (
        <b>{s.data.rollout_parallelism}</b>
      )}
      {error && <span style={{ color: "var(--danger)" }}>{error}</span>}
    </label>
  );
}

export function RolloutsPage() {
  const { current } = useProject();
  const projectId = current!.id;
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const filter = FILTERS.find((f) => f.id === params.get("f")) ?? FILTERS[0];
  const offset = Number(params.get("offset") ?? 0) || 0;
  const list = useAsync(
    () => api.rollouts(projectId, { status: filter.status, active: filter.active, limit: PAGE, offset }),
    [projectId, filter.id, offset],
  );
  const live = (list.data?.items ?? []).some((r) => r.status === "running" || r.status === "dry_run");
  useInterval(() => void list.reload(), 3000, live);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Раскатки</h1>
        </div>
        <div className="actions">
          <Parallelism projectId={projectId} />
        </div>
      </div>
      <section className="card">
        <div className="filters">
          <div className="seg" role="radiogroup" aria-label="Какие раскатки показать">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={f.id === filter.id}
                onClick={() => setParams(f.id === "active" ? {} : { f: f.id })}
              >
                {f.label}
              </button>
            ))}
          </div>
          {list.data && <span className="count">{fmtNumber(list.data.total)}</span>}
        </div>
        {list.error && <ErrorAlert error={list.error} onRetry={() => void list.reload()} />}
        {list.loading && !list.data && <Loading />}
        {list.data && list.data.items.length === 0 && (
          <Empty title={filter.id === "all" ? "Раскаток пока нет" : "Ничего не найдено"} icon={<Rocket size={28} />}>
            Раскатка готовится из карточки заявки кнопкой «Подготовить раскатку»: пробный прогон, утверждение руководителем, канарейка и партии.
          </Empty>
        )}
        {list.data && list.data.items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>№</th>
                  <th>Раскатка</th>
                  <th>Статус</th>
                  <th>Хосты</th>
                  <th>Подготовил</th>
                  <th className="right">Изменена</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((r) => (
                  <tr key={r.id} className="row-click" onClick={() => navigate(`/rollouts/${r.id}`)}>
                    <td className="mono">{r.id}</td>
                    <td style={{ minWidth: 240 }}>
                      <Link to={`/rollouts/${r.id}`} onClick={(e) => e.stopPropagation()}>
                        {r.title}
                      </Link>
                      <div className="faint">
                        {r.template_label}
                        {r.window ? ` · окно «${r.window.name}»` : r.outside_window ? " · вне окна" : ""}
                      </div>
                    </td>
                    <td className="nowrap">
                      <span className={`pill ${ROLLOUT_STATUS_PILL[r.status]}`}>{r.stop_requested && r.status === "running" ? "Останавливается" : r.status_label}</span>
                    </td>
                    <td>
                      <Progress r={r} />
                    </td>
                    <td className="nowrap">{r.prepared_by?.display_name ?? "—"}</td>
                    <td className="right nowrap faint">{fmtDate(r.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && list.data.total > PAGE && (
          <Pager
            total={list.data.total}
            limit={PAGE}
            offset={offset}
            onChange={(o) => {
              const p = new URLSearchParams(params);
              p.set("offset", String(o));
              setParams(p);
            }}
          />
        )}
      </section>
    </>
  );
}
