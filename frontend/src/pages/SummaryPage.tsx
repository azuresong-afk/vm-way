import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CalendarClock, CheckCircle2, Download } from "lucide-react";
import { api } from "../api/client";
import type { Severity, SummaryOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { WeekChart, WeekTable } from "../components/charts/WeekChart";
import { Empty, ErrorAlert, Kpi, Loading, SeverityBadge, StackBar } from "../components/ui";
import { fmtDate, fmtDay, fmtDelta, fmtNumber, plural } from "../lib/format";
import { notifyJobs, waitJob } from "../lib/jobs";
import { useAsync } from "../lib/useAsync";
import { SEVERITY_LABEL } from "../lib/labels";

type Level = Exclude<Severity, "info">;
const LEVELS: Level[] = ["critical", "high", "medium", "low"];
const PERIODS = [
  { id: "3m", label: "3 месяца", phrase: "за 3 месяца" },
  { id: "1y", label: "Год", phrase: "за год" },
] as const;
type Period = (typeof PERIODS)[number]["id"];

/** Герой-блок: открытые уязвимости и заявки, изменение за период, плитки уровней. */
function Hero({ s, phrase }: { s: SummaryOut; phrase: string }) {
  const nav = useNavigate();
  const issues = LEVELS.reduce((a, l) => a + s.vulns_by_severity[l], 0);
  return (
    <section className="card hero2" aria-labelledby="sum-open">
      <div className="hero2-main">
        <div className="inline" style={{ gap: "var(--s1) var(--s2)" }}>
          <span className="hero-number num">{fmtNumber(s.open_vulns)}</span>
          <span
            className="delta-badge"
            style={{
              background: s.delta <= 0 ? "var(--ok-soft)" : "var(--danger-soft)",
              color: s.delta <= 0 ? "var(--ok)" : "var(--danger)",
              fontWeight: 600,
            }}
          >
            {fmtDelta(s.delta)} {phrase}
          </span>
        </div>
        <h2 id="sum-open" className="hero2-title">
          {plural(s.open_vulns, ["открытая уязвимость", "открытые уязвимости", "открытых уязвимостей"])} в {fmtNumber(s.open_tickets)}{" "}
          {plural(s.open_tickets, ["заявке", "заявках", "заявках"])}
        </h2>
        <StackBar counts={s.vulns_by_severity} />
        <span className="faint" style={{ fontSize: 13 }}>
          {s.last_run
            ? `Последний прогон «Сканера»: №${s.last_run.scanner_run_id} от ${fmtDate(s.last_run.finished_at)}`
            : "Прогонов «Сканера» ещё не импортировано"}
        </span>
      </div>
      <div className="sev-tiles2">
        {LEVELS.map((sev) => {
          const n = s.vulns_by_severity[sev];
          const t = s.tickets_by_severity[sev];
          const share = issues ? Math.round((n / issues) * 100) : 0;
          return (
            <button
              key={sev}
              type="button"
              className={`sev-tile2${sev === "critical" && n > 0 ? " hot" : ""}`}
              onClick={() => nav(`/tickets?state=open&severity=${sev}`)}
              aria-label={`${SEVERITY_LABEL[sev]}: ${n} уязвимостей в ${t} заявках. Показать заявки`}
            >
              <span className={`sev sev-${sev}`}>
                <i aria-hidden="true" />
                {SEVERITY_LABEL[sev]}
              </span>
              <b className="num">{fmtNumber(n)}</b>
              <span className="sev-tile2-foot">
                <span className="sev-tile2-share" aria-hidden="true">
                  <span className={`sevbar-fill ${sev}`} style={{ width: `${share}%` }} />
                </span>
                <span className="sev-tile2-meta">
                  <span>
                    {fmtNumber(t)} {plural(t, ["заявка", "заявки", "заявок"])}
                  </span>
                  <span className="num">{share}%</span>
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function Weekly({ s }: { s: SummaryOut }) {
  const [table, setTable] = useState(false);
  return (
    <section className="card card-pad grow-3 stack" aria-labelledby="sum-weeks">
      <div className="inline" style={{ justifyContent: "space-between" }}>
        <h2 id="sum-weeks">Появилось и закрыто по неделям</h2>
        <div className="seg seg-sm" role="radiogroup" aria-label="Вид">
          <button type="button" role="radio" aria-checked={!table} onClick={() => setTable(false)}>
            График
          </button>
          <button type="button" role="radio" aria-checked={table} onClick={() => setTable(true)}>
            Таблица
          </button>
        </div>
      </div>
      <span className="muted" style={{ fontSize: 13 }}>
        С {fmtDay(s.period_start)}: появилось <b>{fmtNumber(s.opened)}</b>, закрыто и подтверждено сканером <b>{fmtNumber(s.closed)}</b>
      </span>
      {table ? <WeekTable weeks={s.weeks} /> : <WeekChart weeks={s.weeks} />}
      {!table && (
        <div className="legend">
          {LEVELS.map((l) => (
            <span key={l} className={`sev sev-${l}`}>
              <i aria-hidden="true" />
              {SEVERITY_LABEL[l]}
            </span>
          ))}
          <span className="faint">вверх — появилось, вниз — закрыто</span>
        </div>
      )}
    </section>
  );
}

function Mttr({ s }: { s: SummaryOut }) {
  const rows = s.mttr.filter((m) => m.severity !== "info");
  const max = Math.max(1, ...rows.map((m) => m.days ?? 0));
  return (
    <section className="card card-pad grow-2 stack" aria-labelledby="sum-mttr">
      <h2 id="sum-mttr">Среднее время устранения</h2>
      <span className="muted" style={{ fontSize: 13 }}>
        От первого обнаружения до подтверждения сканером, по уязвимостям, закрытым за период
      </span>
      <div className="sevbars mttr">
        {rows.map((m) => (
          <div key={m.severity} className="sevbar">
            <SeverityBadge severity={m.severity} />
            <div className="sevbar-track" aria-hidden="true">
              {m.days !== null && <div className={`sevbar-fill ${m.severity}`} style={{ width: `${(m.days / max) * 100}%` }} />}
            </div>
            <span className="num right" title={m.count ? `${m.count} закрыто` : "закрытых нет"}>
              {m.days === null ? "—" : `${fmtNumber(Math.round(m.days))} дн.`}
            </span>
          </div>
        ))}
      </div>
      <div className="kpi-row">
        <div>
          <span className="kpi-label">Ждут проверки</span>
          <Link to="/tickets?status=fixed" className="kpi-mini num">
            {fmtNumber(s.awaiting_check)}
          </Link>
        </div>
        <div>
          <span className="kpi-label">Без исполнителя</span>
          <Link to="/tickets?state=open&assignee=none" className="kpi-mini num">
            {fmtNumber(s.unassigned)}
          </Link>
        </div>
        <div>
          <span className="kpi-label">Регрессии</span>
          <Link to="/tickets?status=regression" className="kpi-mini num">
            {fmtNumber(s.by_status.regression ?? 0)}
          </Link>
        </div>
      </div>
    </section>
  );
}

function TopHosts({ s }: { s: SummaryOut }) {
  return (
    <section className="card grow-3" aria-labelledby="sum-hosts">
      <div className="card-head">
        <h2 id="sum-hosts">Хосты с наибольшим числом открытых уязвимостей</h2>
      </div>
      {s.top_hosts.length === 0 ? (
        <Empty title="Открытых уязвимостей нет" icon={<CheckCircle2 size={28} />} />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Хост</th>
                <th style={{ width: "40%" }}>По уровням</th>
                <th className="right">Уязвимостей</th>
                <th className="right">Заявок</th>
              </tr>
            </thead>
            <tbody>
              {s.top_hosts.map((h) => (
                <tr key={h.host}>
                  <td className="mono">
                    <Link to={`/tickets?state=open&host=${encodeURIComponent(h.host)}`}>{h.host}</Link>
                  </td>
                  <td style={{ verticalAlign: "middle" }}>
                    <StackBar counts={h.by_severity} />
                  </td>
                  <td className="right num">{fmtNumber(h.open)}</td>
                  <td className="right num">{fmtNumber(h.tickets)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Ближайшие окна обслуживания (2 недели): когда, сколько заявок и что закроет. */
function Upcoming({ s }: { s: SummaryOut }) {
  return (
    <section className="card card-pad grow-2 stack" aria-labelledby="sum-windows">
      <div className="inline" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <h2 id="sum-windows">Ближайшие окна</h2>
        <Link to="/windows" style={{ fontSize: 13 }}>
          Окна и план
        </Link>
      </div>
      {s.upcoming_windows.length === 0 ? (
        <Empty title="Окон на ближайшие две недели нет" icon={<CalendarClock size={28} />}>
          Окна обслуживания настраивает руководитель в разделе «Окна и план».
        </Empty>
      ) : (
        <div>
          {s.upcoming_windows.map((o) => (
            <Link key={`${o.window_id}-${o.start}`} to={`/windows?window=${o.window_id}&at=${encodeURIComponent(o.start)}`} className="list-row">
              <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                <span className="ellipsis" style={{ color: o.cancelled ? "var(--text-3)" : "var(--text)", fontWeight: 500 }}>
                  {o.window_name}
                </span>
                <span className="faint ellipsis" style={{ fontSize: 12.5 }}>
                  {fmtDate(o.start)} · {fmtNumber(o.tickets ?? 0)} {plural(o.tickets ?? 0, ["заявка", "заявки", "заявок"])}
                  {o.cancelled ? " · выпадает: блэкаут" : ""}
                </span>
              </span>
              {o.cancelled ? (
                <span className="pill pill-danger">блэкаут</span>
              ) : (
                <span className="pill pill-info" title="Закроет уязвимостей">
                  {fmtNumber(o.will_close ?? 0)}
                </span>
              )}
            </Link>
          ))}
          <span className="faint" style={{ fontSize: 12 }}>
            Справа — сколько уязвимостей закроет окно, если всё пройдёт по плану.
          </span>
        </div>
      )}
    </section>
  );
}

function Verified({ s }: { s: SummaryOut }) {
  return (
    <section className="card card-pad grow-2 stack" aria-labelledby="sum-verified">
      <div className="inline" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <h2 id="sum-verified">Последние подтверждения</h2>
        <Link to="/tickets?status=verified" style={{ fontSize: 13 }}>
          Все закрытые
        </Link>
      </div>
      {s.recent_verified.length === 0 ? (
        <Empty title="Подтверждённых исправлений пока нет">Заявка закрывается, когда повторный прогон «Сканера» не находит уязвимость.</Empty>
      ) : (
        <div>
          {s.recent_verified.map((t) => (
            <Link key={t.id} to={`/tickets/${t.id}`} className="list-row">
              <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                <span className="ellipsis" style={{ color: "var(--text)", fontWeight: 500 }}>
                  №{t.id} · {t.title}
                </span>
                <span className="faint ellipsis" style={{ fontSize: 12.5 }}>
                  {t.evidence ? `прогон №${t.evidence.scanner_run_id} от ${fmtDay(t.evidence.finished_at)}` : "без прогона"} · {fmtNumber(t.hosts)}{" "}
                  {plural(t.hosts, ["хост", "хоста", "хостов"])}
                </span>
              </span>
              <SeverityBadge severity={t.severity} short />
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}

export function SummaryPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const [period, setPeriod] = useState<Period>("3m");
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const projectId = current!.id;
  const s = useAsync(() => api.summary(projectId, period), [projectId, period]);
  const def = PERIODS.find((p) => p.id === period)!;

  const importNew = async () => {
    setImporting(true);
    setImportMsg(null);
    try {
      const job = await api.importNew(projectId);
      notifyJobs();
      setImportMsg("Импорт запущен — сводка обновится после завершения");
      const done = await waitJob(job);
      setImportMsg(done.status === "done" ? "Импорт завершён, сводка обновлена" : (done.error ?? "Импорт ещё идёт"));
      void s.reload();
    } catch (e) {
      setImportMsg((e as Error).message);
    } finally {
      setImporting(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Сводка</h1>
        </div>
        <div className="actions">
          <div className="seg" role="radiogroup" aria-label="Период">
            {PERIODS.map((p) => (
              <button key={p.id} type="button" role="radio" aria-checked={period === p.id} onClick={() => setPeriod(p.id)}>
                {p.label}
              </button>
            ))}
          </div>
          {has("import") && (
            <button type="button" className="btn btn-primary" onClick={importNew} disabled={importing}>
              <Download size={15} aria-hidden="true" />
              {importing ? "Импорт…" : "Импортировать новые прогоны"}
            </button>
          )}
        </div>
      </div>
      {importMsg && <div className="alert alert-info">{importMsg}</div>}
      {s.error && <ErrorAlert error={s.error} onRetry={() => void s.reload()} />}
      {s.loading && !s.data && <Loading />}
      {s.data && (
        <>
          <Hero s={s.data} phrase={def.phrase} />
          <div className="kpis">
            <Kpi label={`Появилось ${def.phrase}`} value={fmtNumber(s.data.opened)} delta="новых уязвимостей" />
            <Kpi
              label={`Закрыто ${def.phrase}`}
              value={fmtNumber(s.data.closed)}
              delta="подтверждено повторной проверкой"
              deltaTone={s.data.closed > 0 ? "good" : undefined}
            />
            <Kpi label="Открытых заявок" value={fmtNumber(s.data.open_tickets)} delta={`из ${fmtNumber(Object.values(s.data.by_status).reduce((a, b) => a + b, 0))} всего`} />
            <Kpi
              label="Критических заявок"
              value={fmtNumber(s.data.tickets_by_severity.critical)}
              tone={s.data.tickets_by_severity.critical > 0 ? "critical" : undefined}
              delta={s.data.tickets_by_severity.critical > 0 ? "в первую очередь" : "нет"}
            />
          </div>
          <div className="row">
            <Weekly s={s.data} />
            <Mttr s={s.data} />
          </div>
          <div className="row">
            <TopHosts s={s.data} />
          </div>
          <div className="row">
            <Upcoming s={s.data} />
            <Verified s={s.data} />
          </div>
        </>
      )}
    </>
  );
}
