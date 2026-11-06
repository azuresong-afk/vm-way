import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Download, FileText } from "lucide-react";
import { api } from "../api/client";
import type { ReportFormat, ReportOut, ReportQuery, ReportVariant } from "../api/types";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { WeekChart, WeekTable } from "../components/charts/WeekChart";
import { Empty, ErrorAlert, Kpi, Loading, SeverityBadge } from "../components/ui";
import { fmtDelta, fmtNumber } from "../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../lib/labels";
import { isoDay, presetRange, type Preset } from "../lib/reportPeriod";
import { useAsync } from "../lib/useAsync";

const PRESETS: { id: Preset; label: string }[] = [
  { id: "month", label: "Месяц" },
  { id: "3m", label: "3 месяца" },
  { id: "year", label: "Год" },
  { id: "contract", label: "Срок договора" },
];

const FORMATS: { id: ReportFormat; label: string; hint: string }[] = [
  { id: "pdf", label: "PDF", hint: "для отправки заказчику" },
  { id: "docx", label: "DOCX", hint: "для правки в Word" },
  { id: "html", label: "HTML", hint: "открывается в браузере" },
  { id: "json", label: "JSON", hint: "для обработки" },
];

function rangeError(from: string, to: string, today: string): string | null {
  if (!from || !to) return "Укажите обе даты периода";
  if (from > to) return "Начало периода позже конца";
  if (to > today) return "Конец периода не может быть в будущем";
  return null;
}

function Move({ r }: { r: ReportOut }) {
  const v = r.totals.vulns;
  return (
    <div className="kpis">
      <Kpi label="Открыто на начало" value={fmtNumber(v.start)} delta="уязвимостей" />
      <Kpi label="Закрыто и подтверждено" value={fmtNumber(v.fixed)} delta="прогонами «Сканера»" deltaTone={v.fixed > 0 ? "good" : undefined} />
      <Kpi
        label="Появилось"
        value={fmtNumber(v.appeared)}
        delta={v.regression ? `и вернулось после исправления: ${fmtNumber(v.regression)}` : "новых за период"}
      />
      <Kpi
        label="Открыто на конец"
        value={fmtNumber(v.end)}
        delta={`${fmtDelta(v.end - v.start)} за период`}
        deltaTone={v.end < v.start ? "good" : v.end > v.start ? "bad" : undefined}
      />
    </div>
  );
}

function Weeks({ r }: { r: ReportOut }) {
  const [table, setTable] = useState(false);
  return (
    <section className="card card-pad grow-3 stack" aria-labelledby="rep-weeks">
      <div className="inline" style={{ justifyContent: "space-between" }}>
        <h2 id="rep-weeks">По неделям</h2>
        <div className="seg seg-sm" role="radiogroup" aria-label="Вид">
          <button type="button" role="radio" aria-checked={!table} onClick={() => setTable(false)}>
            График
          </button>
          <button type="button" role="radio" aria-checked={table} onClick={() => setTable(true)}>
            Таблица
          </button>
        </div>
      </div>
      {table ? <WeekTable weeks={r.weeks} /> : <WeekChart weeks={r.weeks} />}
      {!table && (
        <div className="legend">
          {SEVERITIES.filter((s) => s !== "info").map((l) => (
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

function KeyPoints({ r }: { r: ReportOut }) {
  return (
    <section className="card card-pad grow-2 stack" aria-labelledby="rep-points">
      <h2 id="rep-points">Главное</h2>
      <ul className="report-points">
        {r.key_points.map((p) => (
          <li key={p}>{p}</li>
        ))}
      </ul>
      {r.context.tickets_as_of_now && (
        <span className="faint" style={{ fontSize: 13 }}>
          Период закончился раньше сегодняшнего дня: движение уязвимостей посчитано на его границы, а заявки, исполнители и исключения
          показаны на сегодня.
        </span>
      )}
    </section>
  );
}

const MOVE_HEAD = (
  <>
    <th className="right">На начало</th>
    <th className="right">Закрыто</th>
    <th className="right">Появилось</th>
    <th className="right">Регрессии</th>
    <th className="right">На конец</th>
  </>
);

function MoveCells({ m }: { m: { start: number; fixed: number; appeared: number; regression: number; end: number } }) {
  const cell = (n: number) => <td className={`right num${n ? "" : " faint"}`}>{fmtNumber(n)}</td>;
  return (
    <>
      {cell(m.start)}
      {cell(m.fixed)}
      {cell(m.appeared)}
      {cell(m.regression)}
      <td className="right num">
        <b>{fmtNumber(m.end)}</b>
      </td>
    </>
  );
}

function Tables({ r }: { r: ReportOut }) {
  const people = r.assignees;
  return (
    <>
      <section className="card" aria-labelledby="rep-sev">
        <div className="card-head">
          <h2 id="rep-sev">По уровням опасности</h2>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Уровень</th>
                {MOVE_HEAD}
              </tr>
            </thead>
            <tbody>
              {r.by_severity.map((s) => (
                <tr key={s.severity}>
                  <td>
                    <SeverityBadge severity={s.severity} />
                  </td>
                  <MoveCells m={s} />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="rep-people">
        <div className="card-head">
          <h2 id="rep-people">По исполнителям</h2>
          <span className="faint" style={{ fontSize: 13 }}>
            открытые — по текущему исполнителю, подтверждённые и закрытые — за период
          </span>
        </div>
        {people.length === 0 ? (
          <Empty title="Заявок нет" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Исполнитель</th>
                  <th className="right">Открыто заявок</th>
                  <th className="right">В работе</th>
                  <th className="right">Ждут проверки</th>
                  <th className="right">Открыто уязв.</th>
                  <th className="right">Подтверждено заявок</th>
                  <th className="right">Закрыто уязв.</th>
                </tr>
              </thead>
              <tbody>
                {people.map((p) => (
                  <tr key={p.name}>
                    <td>{p.name}</td>
                    <td className="right num">{fmtNumber(p.open)}</td>
                    <td className="right num">{fmtNumber(p.in_work)}</td>
                    <td className="right num">{fmtNumber(p.awaiting_check)}</td>
                    <td className="right num">{fmtNumber(p.open_vulns)}</td>
                    <td className="right num">{fmtNumber(p.verified)}</td>
                    <td className="right num">{fmtNumber(p.fixed_vulns)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="rep-groups">
        <div className="card-head">
          <h2 id="rep-groups">По группам активов</h2>
          <span className="faint" style={{ fontSize: 13 }}>
            хост из нескольких групп учитывается в каждой
          </span>
        </div>
        {r.groups.length === 0 ? (
          <Empty title="Уязвимостей нет" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Группа</th>
                  <th className="right">Хостов</th>
                  {MOVE_HEAD}
                </tr>
              </thead>
              <tbody>
                {r.groups.map((g) => (
                  <tr key={g.name}>
                    <td>{g.name}</td>
                    <td className="right num">{fmtNumber(g.hosts)}</td>
                    <MoveCells m={g} />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function Proof({ r }: { r: ReportOut }) {
  return (
    <div className="row">
      <section className="card grow-3" aria-labelledby="rep-runs">
        <div className="card-head">
          <h2 id="rep-runs">Прогоны за период</h2>
        </div>
        {r.runs.length === 0 ? (
          <Empty title="За период прогонов не было" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Дата</th>
                  <th>Прогон</th>
                  <th className="right">Закрыто</th>
                  <th className="right">Появилось</th>
                  <th className="right">Регрессии</th>
                </tr>
              </thead>
              <tbody>
                {r.runs.map((x) => (
                  <tr key={x.id}>
                    <td className="num">{x.finished_local}</td>
                    <td>
                      {x.url ? (
                        <a href={x.url} target="_blank" rel="noreferrer noopener">
                          {x.name || "Прогон"}
                        </a>
                      ) : (
                        x.name || "Прогон"
                      )}
                      <div className="faint" style={{ fontSize: 12 }}>
                        №{x.scanner_run_id} «Сканера» · {x.kind_label}
                      </div>
                    </td>
                    <td className="right num">{fmtNumber(x.fixed)}</td>
                    <td className="right num">{fmtNumber(x.appeared)}</td>
                    <td className="right num">{fmtNumber(x.regression)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="card card-pad grow-2 stack" aria-labelledby="rep-tickets">
        <h2 id="rep-tickets">Заявки</h2>
        <div className="kpi-row report-kpi-row">
          <div>
            <span className="kpi-label">Подтверждено</span>
            <span className="kpi-mini num">{fmtNumber(r.totals.tickets_verified)}</span>
          </div>
          <div>
            <span className="kpi-label">Осталось</span>
            <Link to="/tickets?state=open" className="kpi-mini num">
              {fmtNumber(r.totals.tickets_open)}
            </Link>
          </div>
          <div>
            <span className="kpi-label">Исключений</span>
            <Link to="/exceptions?state=active" className="kpi-mini num">
              {fmtNumber(r.totals.tickets_exceptions)}
            </Link>
          </div>
          <div>
            <span className="kpi-label">Не проверено хостов</span>
            <span className="kpi-mini num">{fmtNumber(r.totals.hosts_unverified)}</span>
          </div>
        </div>
        {r.verified.length > 0 && (
          <div>
            {r.verified.slice(0, 6).map((t) => (
              <Link key={t.id} to={`/tickets/${t.id}`} className="list-row">
                <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                  <span className="ellipsis" style={{ color: "var(--text)", fontWeight: 500 }}>
                    №{t.id} · {t.title}
                  </span>
                  <span className="faint ellipsis" style={{ fontSize: 12.5 }}>
                    подтверждено {t.closed_local}
                    {t.evidence?.scanner_run_id ? ` прогоном №${t.evidence.scanner_run_id}` : ""}
                  </span>
                </span>
                <SeverityBadge severity={t.severity} short />
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export function ReportsPage() {
  const { current } = useProject();
  const project = current!;
  const today = useMemo(() => isoDay(new Date()), []);
  const [preset, setPreset] = useState<Preset>("3m");
  const [range, setRange] = useState(() => presetRange("3m", today, project));
  const [variant, setVariant] = useState<ReportVariant>("full");
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const invalid = rangeError(range.from, range.to, today);
  const query: ReportQuery = { from: range.from, to: range.to, variant };
  const r = useAsync(() => api.report(project.id, query), [project.id, range.from, range.to, variant], !invalid);

  const choose = (p: Exclude<Preset, "custom">) => {
    setPreset(p);
    setRange(presetRange(p, today, project));
  };
  const setDay = (key: "from" | "to", value: string) => {
    setPreset("custom");
    setRange((x) => ({ ...x, [key]: value }));
  };

  const download = async (format: ReportFormat) => {
    setBusy(format);
    setFileError(null);
    try {
      const { blob, name } = await api.reportFile(project.id, query, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setFileError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(project)}</span>
          <h1>Отчёты</h1>
        </div>
      </div>

      <section className="card card-pad stack" aria-labelledby="rep-params">
        <h2 id="rep-params">Отчёт о ходе устранения</h2>
        <span className="muted" style={{ fontSize: 13 }}>
          Что было на начало периода, что закрыто и подтверждено сканером, что осталось — по уровням, исполнителям и группам активов.
        </span>
        <div className="report-params">
          <div className="field">
            <span id="rep-period">Период</span>
            <div className="seg" role="radiogroup" aria-labelledby="rep-period">
              {PRESETS.filter((p) => p.id !== "contract" || project.period_from).map((p) => (
                <button key={p.id} type="button" role="radio" aria-checked={preset === p.id} onClick={() => choose(p.id as Exclude<Preset, "custom">)}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <div className="report-dates">
            <label className="field">
              <span>С</span>
              <input className="input" type="date" value={range.from} max={today} onChange={(e) => setDay("from", e.target.value)} />
            </label>
            <label className="field">
              <span>По</span>
              <input className="input" type="date" value={range.to} max={today} onChange={(e) => setDay("to", e.target.value)} />
            </label>
          </div>
          <div className="field">
            <span id="rep-variant">Вариант</span>
            <div className="seg" role="radiogroup" aria-labelledby="rep-variant">
              {(["full", "brief"] as ReportVariant[]).map((v) => (
                <button key={v} type="button" role="radio" aria-checked={variant === v} onClick={() => setVariant(v)}>
                  {v === "full" ? "Полный" : "Краткий"}
                </button>
              ))}
            </div>
          </div>
        </div>
        <span className="faint" style={{ fontSize: 13 }}>
          {variant === "full"
            ? "Полный — со списками подтверждённых и открытых заявок."
            : "Краткий — только итоги и разбивки, без списков заявок."}{" "}
          Границы периода — по московскому времени. Сроков устранения в отчёте нет.
        </span>
        <div className="report-formats" role="group" aria-label="Скачать отчёт">
          {FORMATS.map((f, i) => (
            <button
              key={f.id}
              type="button"
              className={`btn${i === 0 ? " btn-primary" : ""}`}
              onClick={() => void download(f.id)}
              disabled={!!invalid || busy !== null}
              title={f.hint}
            >
              <Download size={15} aria-hidden="true" />
              {busy === f.id ? "Готовится…" : f.label}
            </button>
          ))}
        </div>
        {fileError && <ErrorAlert error={fileError} />}
      </section>

      {invalid && <div className="alert alert-warn">{invalid}</div>}
      {!invalid && r.error && <ErrorAlert error={r.error} onRetry={() => void r.reload()} />}
      {!invalid && r.loading && !r.data && <Loading label="Собираем отчёт…" />}
      {!invalid && r.data && (
        <div className={`stack${r.loading ? " is-stale" : ""}`} aria-busy={r.loading}>
          <h2 className="report-preview-title">
            <FileText size={18} aria-hidden="true" /> Предпросмотр · {r.data.context.period.label}
          </h2>
          <Move r={r.data} />
          <div className="row">
            <Weeks r={r.data} />
            <KeyPoints r={r.data} />
          </div>
          <Proof r={r.data} />
          <Tables r={r.data} />
        </div>
      )}
    </>
  );
}
