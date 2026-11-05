import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { RefreshCw, Server } from "lucide-react";
import { api } from "../api/client";
import type { AssetSyncOut, Criticality } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { Pager } from "../components/Pager";
import { CriticalityBadge, Empty, ErrorAlert, Loading } from "../components/ui";
import { fmtDate, fmtNumber, plural } from "../lib/format";
import { CRITICALITIES, CRITICALITY_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

function syncText(r: AssetSyncOut): string {
  const parts = [`${fmtNumber(r.assets)} ${plural(r.assets, ["актив", "актива", "активов"])}`];
  if (r.created) parts.push(`новых ${fmtNumber(r.created)}`);
  if (r.removed) parts.push(`удалено ${fmtNumber(r.removed)}`);
  if (r.groups_removed) parts.push(`групп удалено ${fmtNumber(r.groups_removed)}`);
  return `Обновлено из «Сканера»: ${parts.join(", ")}.`;
}

/** Активы «Сканера»: группы, владельцы, критичность и теги — основа правил назначения и охвата окон. */
export function AssetsPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const [params, setParams] = useSearchParams();
  const group = params.get("group") ?? "";
  const tag = params.get("tag") ?? "";
  const criticality = (params.get("criticality") ?? "") as Criticality | "";
  const q = params.get("q") ?? "";
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const limit = 50;
  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };
  const [text, setText] = useState(q);
  useEffect(() => {
    if (text.trim() === q) return;
    const t = window.setTimeout(() => set({ q: text.trim() || null }), 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const facets = useAsync(() => api.assetFacets(projectId), [projectId]);
  const page = useAsync(
    () =>
      api.assets(projectId, {
        group: group || undefined,
        tag: tag || undefined,
        criticality: criticality || undefined,
        q: q || undefined,
        limit,
        offset,
      }),
    [projectId, group, tag, criticality, q, offset],
  );
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sync = async () => {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      const r = await api.syncAssets(projectId);
      setNote(syncText(r) + (r.errors.length ? ` Не ответили: ${r.errors.map((e) => e.error).join("; ")}` : ""));
      await Promise.all([facets.reload(), page.reload()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const f = facets.data;
  const filtered = !!(group || tag || criticality || q);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Активы</h1>
        </div>
        {has("import") && (
          <div className="actions">
            <button type="button" className="btn" onClick={() => void sync()} disabled={busy}>
              <RefreshCw size={15} aria-hidden="true" /> {busy ? "Обновление…" : "Обновить из «Сканера»"}
            </button>
          </div>
        )}
      </div>
      {note && <div className="alert alert-info" role="status">{note}</div>}
      {error && <ErrorAlert error={error} />}

      <section className="card" aria-labelledby="groups-head">
        <div className="card-head">
          <h2 id="groups-head">Группы активов</h2>
          {f?.synced_at && <span className="faint" style={{ fontSize: 13 }}>из «Сканера», {fmtDate(f.synced_at)}</span>}
        </div>
        {facets.error && <ErrorAlert error={facets.error} onRetry={() => void facets.reload()} />}
        {facets.loading && !f && <Loading />}
        {f && f.groups.length === 0 && (
          <Empty title="Групп пока нет" icon={<Server size={28} />}>
            Группы и активы приходят из «Сканера» при импорте прогона или по кнопке «Обновить из «Сканера»».
          </Empty>
        )}
        {f && f.groups.length > 0 && (
          <div className="group-chips" role="group" aria-label="Фильтр по группе">
            {f.groups.map((g) => (
              <button
                key={g.name}
                type="button"
                className="chip"
                aria-pressed={group === g.name}
                onClick={() => set({ group: group === g.name ? null : g.name })}
                title={`${g.assets} ${plural(g.assets, ["актив", "актива", "активов"])}, открытых заявок: ${g.open_tickets}`}
              >
                {g.name}
                <span className="picker-count">{g.assets}</span>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="assets-head">
        <div className="card-head">
          <h2 id="assets-head">Хосты</h2>
          {page.data && <span className="faint" style={{ fontSize: 13 }}>{fmtNumber(page.data.total)}</span>}
        </div>
        <div className="filters">
          <input
            className="input"
            type="search"
            placeholder="Адрес, имя или владелец"
            aria-label="Поиск по активам"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <select className="select" aria-label="Критичность" value={criticality} onChange={(e) => set({ criticality: e.target.value || null })}>
            <option value="">Любая критичность</option>
            {CRITICALITIES.map((c) => (
              <option key={c} value={c}>
                {CRITICALITY_LABEL[c]} · {f?.criticality[c] ?? 0}
              </option>
            ))}
          </select>
          {(f?.tags.length ?? 0) > 0 && (
            <select className="select" aria-label="Тег" value={tag} onChange={(e) => set({ tag: e.target.value || null })}>
              <option value="">Все теги</option>
              {f!.tags.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name} · {t.assets}
                </option>
              ))}
            </select>
          )}
          {filtered && (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => { setText(""); set({ group: null, tag: null, criticality: null, q: null }); }}>
              Сбросить
            </button>
          )}
        </div>
        {page.error && <ErrorAlert error={page.error} onRetry={() => void page.reload()} />}
        {page.loading && !page.data && <Loading />}
        {page.data && page.data.items.length === 0 && (
          <Empty title={filtered ? "Ничего не найдено" : "Активов пока нет"} icon={<Server size={28} />}>
            {filtered ? "Измените фильтры." : "Активы приходят из «Сканера» вместе с прогонами."}
          </Empty>
        )}
        {page.data && page.data.items.length > 0 && (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Хост</th>
                    <th>Группы</th>
                    <th>Владелец</th>
                    <th>Критичность</th>
                    <th>Теги</th>
                    <th className="right">Открытые заявки</th>
                  </tr>
                </thead>
                <tbody>
                  {page.data.items.map((a) => (
                    <tr key={a.id}>
                      <td className="nowrap">
                        <span className="mono">{a.address}</span>
                        <div className="faint">{[a.hostname, a.os_guess].filter(Boolean).join(" · ") || "—"}</div>
                      </td>
                      <td>
                        {a.groups.length ? (
                          <span className="asset-cell">
                            {a.groups.map((g) => (
                              <button key={g} type="button" className="tag tag-muted" style={{ border: 0, cursor: "pointer" }} onClick={() => set({ group: g })}>
                                {g}
                              </button>
                            ))}
                          </span>
                        ) : (
                          <span className="faint">—</span>
                        )}
                      </td>
                      <td>{a.owner || <span className="faint">—</span>}</td>
                      <td className="nowrap">
                        <CriticalityBadge value={a.criticality} />
                      </td>
                      <td>{a.tags.length ? a.tags.join(", ") : <span className="faint">—</span>}</td>
                      <td className="right">
                        {a.open_tickets ? (
                          <Link to={`/tickets?host=${encodeURIComponent(a.address)}`}>{fmtNumber(a.open_tickets)}</Link>
                        ) : (
                          <span className="faint">0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager total={page.data.total} offset={offset} limit={limit} onChange={(o) => set({ offset: o ? String(o) : null })} />
          </>
        )}
      </section>
    </>
  );
}
