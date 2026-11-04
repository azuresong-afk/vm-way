import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { AlertTriangle, ExternalLink, MessageSquare, Power, RotateCcw, Send } from "lucide-react";
import { api } from "../api/client";
import type { CommentOut, HistoryEntry, TicketDetail, TicketStatus, VerificationOut } from "../api/types";
import { HostsProgress } from "../components/TicketsTable";
import { TicketActions } from "../components/TicketActions";
import { Commands, CriticalityBadge, Empty, ErrorAlert, HostStatusPill, Loading, RefTags, SeverityBadge, StatusPill } from "../components/ui";
import { fmtDate, fmtDay, fmtNumber, plural } from "../lib/format";
import {
  KIND_LABEL,
  MODULE_LABEL,
  OUTCOME_LABEL,
  OUTCOME_PILL,
  SEVERITY_LABEL,
  STATUS_LABEL,
} from "../lib/labels";
import { useAsync } from "../lib/useAsync";

const isHttp = (u: string) => /^https?:\/\//i.test(u);

function refLabel(url: string): string {
  try {
    const u = new URL(url);
    const tail = decodeURIComponent(u.pathname.split("/").filter(Boolean).at(-1) ?? "");
    return tail ? `${u.host} · ${tail.replace(/\.html?$/, "")}` : u.host;
  } catch {
    return url;
  }
}

/** «Что сделать»: шаги и команды «Сканера» под ОС заявки, проверка, перезагрузка, бюллетени. */
function WhatToDo({ t }: { t: TicketDetail }) {
  const a = t.action;
  const steps = a.steps ?? [];
  const refs = (a.references ?? []).filter(isHttp);
  return (
    <section className="card card-pad stack" aria-labelledby="todo-head" style={{ gap: "var(--s2)" }}>
      <h2 id="todo-head">Что сделать</h2>
      {a.reboot && (
        <div className="alert alert-warn">
          <Power size={16} aria-hidden="true" />
          <span>Нужна перезагрузка хоста — планируйте исправление на окно обслуживания.</span>
        </div>
      )}
      {steps.length > 0 ? (
        <ol className="fix-steps">
          {steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      ) : (
        <span className="muted">«Сканер» не дал пошаговой инструкции для этого действия.</span>
      )}
      {(a.commands?.length ?? 0) > 0 && <Commands title={t.os ? `Команды · ${t.os}` : "Команды"} lines={a.commands ?? []} />}
      {(a.verify?.length ?? 0) > 0 && <Commands title="Проверить вручную" lines={a.verify ?? []} />}
      {a.details && (
        <details className="fix-details">
          <summary>Подробности{a.details_source ? ` · ${a.details_source}` : ""}</summary>
          <p className="muted" style={{ whiteSpace: "pre-wrap" }}>
            {a.details}
          </p>
        </details>
      )}
      <dl className="kv">
        {(a.packages?.length ?? 0) > 0 && (
          <>
            <dt>Пакеты</dt>
            <dd>
              {a.packages!.map((p) => (
                <span key={p} className="tag tag-muted">
                  {p}
                </span>
              ))}
              {a.fixed_version && <span className="faint">до {a.fixed_version}</span>}
            </dd>
          </>
        )}
        {a.software && (
          <>
            <dt>ПО</dt>
            <dd>{a.software}</dd>
          </>
        )}
        <dt>CVE и БДУ</dt>
        <dd>
          <RefTags cve={a.cves ?? t.cves} bdu={a.bdu_ids ?? []} />
        </dd>
        {(a.advisories?.length ?? 0) > 0 && (
          <>
            <dt>Бюллетени</dt>
            <dd>
              {a.advisories!.map((x) => (
                <span key={x} className="tag tag-muted">
                  {x}
                </span>
              ))}
            </dd>
          </>
        )}
      </dl>
      {refs.length > 0 && (
        <div className="links">
          {refs.slice(0, 8).map((r) => (
            <a key={r} href={r} target="_blank" rel="noopener noreferrer">
              <ExternalLink size={13} aria-hidden="true" /> {refLabel(r)}
            </a>
          ))}
        </div>
      )}
    </section>
  );
}

function Hosts({ t }: { t: TicketDetail }) {
  return (
    <section className="card" aria-labelledby="hosts-head">
      <div className="card-head">
        <h2 id="hosts-head">Хосты</h2>
        <HostsProgress t={t} />
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Хост</th>
              <th>Актив</th>
              <th>Установлено</th>
              <th>Статус</th>
              <th>Причина</th>
              <th className="right">Проверка</th>
            </tr>
          </thead>
          <tbody>
            {t.hosts.map((h) => (
              <tr key={h.id}>
                <td className="nowrap">
                  <span className="mono">{h.host}</span>
                  {h.asset?.hostname && <div className="faint">{h.asset.hostname}</div>}
                </td>
                <td style={{ minWidth: 160 }}>
                  {h.asset ? (
                    <span className="asset-cell">
                      <CriticalityBadge value={h.asset.criticality} />
                      {h.asset.groups.map((g) => (
                        <Link key={g} className="tag tag-muted" to={`/tickets?group=${encodeURIComponent(g)}`}>
                          {g}
                        </Link>
                      ))}
                      {h.asset.owner && <span className="faint">{h.asset.owner}</span>}
                    </span>
                  ) : (
                    <span className="faint" title="Хоста нет среди активов «Сканера»">—</span>
                  )}
                </td>
                <td className="mono">{h.installed || <span className="faint">—</span>}</td>
                <td>
                  <HostStatusPill status={h.status} />
                </td>
                <td style={{ minWidth: 180 }}>{h.reason || h.note || <span className="faint">—</span>}</td>
                <td className="right nowrap">
                  {h.last_check ? (
                    <>
                      №{h.last_check.scanner_run_id} <span className="faint">· {fmtDay(h.last_check.finished_at)}</span>
                    </>
                  ) : (
                    <span className="faint">не было</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Vulns({ t }: { t: TicketDetail }) {
  return (
    <section className="card" aria-labelledby="vulns-head">
      <div className="card-head">
        <h2 id="vulns-head">Уязвимости</h2>
        <span className="count">
          {fmtNumber(t.vulns_open)} из {fmtNumber(t.vulns_total)} открыто
        </span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Идентификатор</th>
              <th>Название</th>
              <th>Хост</th>
              <th>Уровень</th>
              <th>Состояние</th>
            </tr>
          </thead>
          <tbody>
            {t.vulnerabilities.map((v) => (
              <tr key={v.id} className={v.state === "fixed" ? "is-fp" : undefined}>
                <td>
                  <RefTags cve={v.cve_ids.length ? v.cve_ids : [v.vuln_id]} bdu={v.bdu_ids} limit={2} />
                </td>
                <td style={{ minWidth: 180 }}>
                  {v.title}
                  {v.software && (
                    <span className="faint ticket-sub">
                      {v.software} {v.software_version}
                    </span>
                  )}
                </td>
                <td className="nowrap">
                  <span className="mono">
                    {v.host}
                    {v.port ? <span className="faint">:{v.port}</span> : null}
                  </span>
                  <span className="faint ticket-sub">{MODULE_LABEL[v.module] ?? v.module}</span>
                </td>
                <td className="nowrap">
                  <SeverityBadge severity={v.severity} />
                  {v.cvss !== null && <span className="faint ticket-sub">CVSS {v.cvss}</span>}
                </td>
                <td className="nowrap">
                  {v.state === "fixed" ? (
                    <span className="pill pill-ok">Исправлена</span>
                  ) : v.is_regression ? (
                    <span className="pill pill-danger">Регрессия</span>
                  ) : (
                    <span className="pill pill-muted">Открыта</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Facts({ t }: { t: TicketDetail }) {
  return (
    <section className="card card-pad stack" aria-labelledby="facts-head">
      <h2 id="facts-head">Сведения</h2>
      <dl className="kv">
        <dt>Исполнитель</dt>
        <dd>{t.assignee ? t.assignee.display_name : <span className="faint">не назначена</span>}</dd>
        <dt>Окно</dt>
        <dd>
          {t.window ? (
            <Link to={`/windows?window=${t.window.id}`}>{t.window.name}</Link>
          ) : (
            <span className="faint">не запланирована</span>
          )}
        </dd>
        <dt>Наблюдатели</dt>
        <dd>{t.watchers.length ? t.watchers.map((w) => w.display_name).join(", ") : <span className="faint">нет</span>}</dd>
        <dt>Уровень</dt>
        <dd>
          <SeverityBadge severity={t.severity} />
          {t.severity_overridden && (
            <span className="faint" title={t.override_reason}>
              (у «Сканера» — {SEVERITY_LABEL[t.scanner_severity].toLowerCase()})
            </span>
          )}
        </dd>
        <dt>Приоритет</dt>
        <dd>{t.priority.rank ? `#${t.priority.rank} в плане «Сканера»` : <span className="faint">—</span>}</dd>
        <dt>Вид</dt>
        <dd>{t.action.kind_label ?? KIND_LABEL[t.kind] ?? t.kind}</dd>
        {t.os && (
          <>
            <dt>ОС</dt>
            <dd>{t.os}</dd>
          </>
        )}
        <dt>Создана</dt>
        <dd>{fmtDate(t.created_at)}</dd>
        <dt>Изменена</dt>
        <dd>{fmtDate(t.updated_at)}</dd>
        {t.closed_at && (
          <>
            <dt>Закрыта</dt>
            <dd>{fmtDate(t.closed_at)}</dd>
          </>
        )}
      </dl>
      {t.evidence && (
        <div className="alert alert-ok">
          <span style={{ flex: 1 }}>
            <b>Доказательство закрытия:</b> прогон «{t.evidence.run_name}» (№{t.evidence.scanner_run_id} «Сканера») от {fmtDate(t.evidence.finished_at)}.{" "}
            {t.evidence.url && (
              <a href={t.evidence.url} target="_blank" rel="noopener noreferrer">
                Открыть в «Сканере» <ExternalLink size={12} aria-hidden="true" />
              </a>
            )}
          </span>
        </div>
      )}
    </section>
  );
}

const V_STATUS: Record<VerificationOut["status"], [string, string]> = {
  requested: ["Запрошена", "pill-info pill-running"],
  running: ["Идёт", "pill-info pill-running"],
  done: ["Завершена", "pill-ok"],
  failed: ["Ошибка", "pill-danger"],
};

function Checks({ t }: { t: TicketDetail }) {
  if (!t.verifications.length) return null;
  return (
    <section className="card card-pad stack" aria-labelledby="checks-head">
      <h2 id="checks-head">Повторные проверки</h2>
      <div>
        {t.verifications.map((v) => {
          const outcome = v.result?.outcome;
          const [label, pill] = outcome ? [OUTCOME_LABEL[outcome], OUTCOME_PILL[outcome]] : V_STATUS[v.status];
          const c = v.result?.counts;
          return (
            <div key={v.id} className="list-row" style={{ alignItems: "flex-start" }}>
              <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 2 }}>
                <span>
                  {v.scanner_run_id ? `Прогон №${v.scanner_run_id}` : "Прогон не запущен"} ·{" "}
                  <span className="faint">
                    {fmtNumber(v.targets.length)} {plural(v.targets.length, ["хост", "хоста", "хостов"])}
                  </span>
                </span>
                <span className="faint" style={{ fontSize: 12.5 }}>
                  {fmtDate(v.created_at)}
                  {c ? ` · подтверждено ${c.confirmed}, не подтверждено ${c.not_confirmed}, не проверено ${c.unverified}` : ""}
                </span>
                {v.error && <span className="faint" style={{ fontSize: 12.5, color: "var(--danger)" }}>{v.error}</span>}
              </span>
              <span className={`pill ${pill}`}>{label}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

type FeedItem = { at: string; key: string } & ({ type: "h"; h: HistoryEntry } | { type: "c"; c: CommentOut });

/** Событие истории — безличной фразой: пол автора неизвестен, «Система» — тоже автор. */
function historyText(h: HistoryEntry): string {
  const st = (s: string) => STATUS_LABEL[s as TicketStatus] ?? s;
  const d = h.details ?? {};
  const why = d.reason ? `. Причина: ${String(d.reason)}` : "";
  switch (h.action) {
    case "created":
      return `Заявка создана по прогону №${d.scanner_run_id ?? "—"}`;
    case "status":
      return `Статус: ${st(h.from)} → ${st(h.to)}${why}`;
    case "assigned":
      return d.via === "take" ? "Заявка взята в работу" : `Исполнитель: ${h.to}${h.from ? ` (вместо ${h.from})` : ""}`;
    case "unassigned":
      return `Исполнитель снят: ${h.from}`;
    case "override":
      return `Уровень и приоритет: ${h.from} → ${h.to}${why}`;
    case "host_added":
      return `Добавлен хост ${h.to}`;
    case "vulns_moved":
      return `Уязвимости (${String(d.count ?? "")}) перенесены в заявку №${h.to}`;
    case "regression":
      return `Регрессия: ${h.to}`;
    case "window":
      return h.to ? `Поставлена в окно «${h.to}»${h.from ? ` (вместо «${h.from}»)` : ""}` : `Снята с окна «${h.from}»`;
    case "verify_requested":
      return `Запущена повторная проверка: ${h.to}`;
    case "verify_result":
      return `Итог повторной проверки: ${OUTCOME_LABEL[h.to] ?? h.to}`;
    default:
      return `${h.action}${h.to ? `: ${h.to}` : ""}`;
  }
}

function Activity({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const hist = useAsync(() => api.ticketHistory(t.id), [t.id, t.updated_at]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const items: FeedItem[] = [
    ...(hist.data?.history ?? []).map((h) => ({ at: h.at, key: `h${h.id}`, type: "h" as const, h })),
    ...(hist.data?.comments ?? []).map((c) => ({ at: c.at, key: `c${c.id}`, type: "c" as const, c })),
  ].sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.key < b.key ? 1 : -1));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.comment(t.id, text.trim());
      setText("");
      await hist.reload();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card card-pad stack" aria-labelledby="act-head">
      <h2 id="act-head">История и комментарии</h2>
      {t.can.comment && (
        <form onSubmit={submit} className="stack" style={{ gap: 8 }}>
          <label className="sr-only" htmlFor="comment">
            Комментарий
          </label>
          <textarea
            id="comment"
            className="textarea comment-input"
            placeholder="Комментарий: что сделано, что мешает…"
            value={text}
            onChange={(e) => setText(e.target.value)}
            maxLength={10000}
          />
          <div className="inline" style={{ justifyContent: "space-between" }}>
            <small className="faint">Комментарий нельзя изменить или удалить — он остаётся в истории заявки.</small>
            <button type="submit" className="btn btn-sm" disabled={busy || !text.trim()}>
              <Send size={14} aria-hidden="true" /> Отправить
            </button>
          </div>
          {error && <ErrorAlert error={error} />}
        </form>
      )}
      {hist.error && <ErrorAlert error={hist.error} onRetry={() => void hist.reload()} />}
      {hist.loading && !hist.data && <Loading />}
      {hist.data && items.length === 0 && <Empty title="Событий пока нет" icon={<MessageSquare size={28} />} />}
      <ol className="timeline">
        {items.map((it) =>
          it.type === "c" ? (
            <li key={it.key} className={`timeline-item ${it.c.kind === "system" ? "is-system" : "is-comment"}`}>
              <span className="timeline-dot" aria-hidden="true" />
              <div className="timeline-body">
                <div className="timeline-meta">
                  <b>{it.c.author ? it.c.author.display_name : "Система"}</b>
                  <span className="faint">{fmtDate(it.c.at)}</span>
                </div>
                <div className={it.c.kind === "system" ? "muted" : "comment-text"}>{it.c.body}</div>
              </div>
            </li>
          ) : (
            <li key={it.key} className="timeline-item">
              <span className="timeline-dot" aria-hidden="true" />
              <div className="timeline-body">
                <div className="timeline-meta">
                  <span>{historyText(it.h)}</span>
                  <span className="faint nowrap">
                    {it.h.actor ? it.h.actor.display_name : "Система"} · {fmtDate(it.h.at)}
                  </span>
                </div>
              </div>
            </li>
          ),
        )}
      </ol>
    </section>
  );
}

export function TicketPage() {
  const { id } = useParams();
  const ticketId = Number(id);
  const t = useAsync(() => api.ticket(ticketId), [ticketId], Number.isInteger(ticketId) && ticketId > 0);
  if (!Number.isInteger(ticketId) || ticketId <= 0) return <div className="card"><Empty title="Заявка не найдена" /></div>;
  if (t.error) return <ErrorAlert error={t.error} onRetry={() => void t.reload()} />;
  if (!t.data) return <Loading />;
  const d = t.data;
  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to="/tickets">Заявки</Link> <span aria-hidden="true">/</span> <span>№{d.id}</span>
          </span>
          <h1>{d.title}</h1>
          <span className="inline" style={{ gap: 8, marginTop: 4 }}>
            <StatusPill status={d.status} />
            <SeverityBadge severity={d.severity} />
            {d.is_regression && d.status !== "regression" && (
              <span className="pill pill-danger">
                <RotateCcw size={12} aria-hidden="true" /> была регрессия
              </span>
            )}
            {d.reboot && <span className="pill pill-warn">нужна перезагрузка</span>}
            {d.status === "no_vendor_fix" && (
              <span className="pill pill-muted">
                <AlertTriangle size={12} aria-hidden="true" /> ждём исправления производителя
              </span>
            )}
          </span>
        </div>
      </div>
      <TicketActions t={d} onChanged={() => void t.reload()} />
      <div className="row">
        <div className="grow-3 stack" style={{ gap: "var(--s3)" }}>
          <WhatToDo t={d} />
          <Hosts t={d} />
          <Vulns t={d} />
        </div>
        <div className="grow-2 stack" style={{ gap: "var(--s3)" }}>
          <Facts t={d} />
          <Checks t={d} />
          <Activity t={d} onChanged={() => void t.reload()} />
        </div>
      </div>
    </>
  );
}
