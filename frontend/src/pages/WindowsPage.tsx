import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Ban, CalendarClock, ChevronLeft, ChevronRight, ListPlus, Pencil, Plus, RotateCcw, X } from "lucide-react";
import { api } from "../api/client";
import type { CalendarItem, PlanItem, WindowKind, WindowOut, WindowPlanOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { WindowFormModal } from "../components/WindowForm";
import { Empty, ErrorAlert, Loading, SeverityBadge, StackBar } from "../components/ui";
import { fmtNumber, plural } from "../lib/format";
import { KIND_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { fmtMinutes, fmtRange, fmtZoned } from "../lib/zoned";

function scopeText(w: WindowOut): string {
  return w.hosts.length ? `${fmtNumber(w.hosts.length)} ${plural(w.hosts.length, ["хост", "хоста", "хостов"])}` : "все хосты";
}

function WindowRow({ w, selected, onSelect }: { w: WindowOut; selected: boolean; onSelect: () => void }) {
  const dim = !w.is_active || w.past;
  return (
    <button type="button" className={`window-row${selected ? " selected" : ""}`} onClick={onSelect} aria-pressed={selected}>
      <span className="window-row-main">
        <span className="ellipsis" style={{ fontWeight: 500, color: dim ? "var(--text-3)" : "var(--text)" }}>
          {w.name}
        </span>
        <span className="faint ellipsis" style={{ fontSize: 12.5 }}>
          {w.schedule} · {scopeText(w)}
        </span>
        {w.kind !== "blackout" && (
          <span className="faint ellipsis" style={{ fontSize: 12.5 }}>
            {!w.is_active
              ? "отключено"
              : w.next
                ? `ближайшее: ${fmtZoned(w.next.start, w.timezone)}`
                : "предстоящих дат нет"}
          </span>
        )}
      </span>
      {w.kind !== "blackout" ? (
        <span className="pill pill-info" title="Открытых заявок в окне">
          {fmtNumber(w.tickets)}
        </span>
      ) : (
        !w.past && w.is_active && <span className="pill pill-danger">стоп</span>
      )}
    </button>
  );
}

/** Временная шкала даты окна: заявки по порядку, оценка длительности, перезагрузки. */
function Timeline({ plan, tz }: { plan: NonNullable<WindowPlanOut["plan"]>; tz: string }) {
  const start = new Date(plan.occurrence.start).getTime();
  const end = new Date(plan.occurrence.end).getTime();
  const span = Math.max(1, end - start);
  const ticks = useMemo(() => {
    const hours = span / 3600_000;
    const step = hours <= 6 ? 1 : hours <= 12 ? 2 : hours <= 24 ? 4 : 24;
    const out: number[] = [];
    for (let t = 0; t <= hours + 1e-9; t += step) out.push(t);
    return out;
  }, [span]);
  const pct = (iso: string) => Math.min(100, Math.max(0, ((new Date(iso).getTime() - start) / span) * 100));
  const rows = plan.items.filter((i) => i.hosts.length);
  const idle = plan.items.filter((i) => !i.hosts.length);
  return (
    <div className="plan-timeline">
      <div className="plan-axis" aria-hidden="true">
        <span />
        <div className="plan-track">
          {ticks.map((h) => (
            <span key={h} className="plan-tick" style={{ left: `${(h * 3600_000 * 100) / span}%` }}>
              {fmtZoned(new Date(start + h * 3600_000).toISOString(), tz, false)}
            </span>
          ))}
        </div>
      </div>
      {rows.map((i) => (
        <PlanRow key={i.ticket_id} i={i} left={pct(i.start!)} right={pct(i.end!)} tz={tz} />
      ))}
      {idle.map((i) => (
        <div key={i.ticket_id} className="plan-row">
          <PlanLabel i={i} />
          <div className="plan-track">
            <span className="faint" style={{ fontSize: 12.5, paddingLeft: 8 }}>
              нет хостов в этой дате окна: {i.skipped_hosts.map((s) => s.reason).filter((v, k, a) => a.indexOf(v) === k).join(", ")}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function PlanLabel({ i }: { i: PlanItem }) {
  return (
    <div className="plan-label">
      <Link to={`/tickets/${i.ticket_id}`} className="ticket-title ellipsis" title={i.title}>
        №{i.ticket_id} · {i.title}
      </Link>
      <span className="ticket-sub faint">
        <SeverityBadge severity={i.severity} short />
        <span>{KIND_LABEL[i.kind] ?? i.kind}</span>
        <span>
          {fmtNumber(i.hosts.length)} {plural(i.hosts.length, ["хост", "хоста", "хостов"])}
        </span>
        {i.assignee && <span>{i.assignee}</span>}
      </span>
    </div>
  );
}

function PlanRow({ i, left, right, tz }: { i: PlanItem; left: number; right: number; tz: string }) {
  const title = `${fmtZoned(i.start, tz, false)}–${fmtZoned(i.end, tz, false)} · ≈ ${fmtMinutes(i.estimate_minutes)} · ${fmtNumber(i.vulns)} ${plural(i.vulns, ["уязвимость", "уязвимости", "уязвимостей"])}${i.fits ? "" : " · не помещается в окно"}${i.skipped_hosts.length ? ` · вне плана: ${i.skipped_hosts.length}` : ""}`;
  return (
    <div className="plan-row">
      <PlanLabel i={i} />
      <div className="plan-track">
        <span
          className={`plan-bar sev-fill-${i.severity}${i.fits ? "" : " overflow"}`}
          style={{ left: `${left}%`, width: `${Math.max(1.5, (i.fits ? right : 100) - left)}%` }}
          title={title}
          aria-label={title}
        >
          {i.reboot && <RotateCcw size={12} aria-hidden="true" />}
          <span className="plan-bar-text">{i.fits ? fmtMinutes(i.estimate_minutes) : "не помещается"}</span>
        </span>
      </div>
    </div>
  );
}

function PlanPanel({
  data,
  canEdit,
  canPlace,
  onAt,
  onEdit,
  onRemoveTicket,
}: {
  data: WindowPlanOut;
  canEdit: boolean;
  canPlace: boolean;
  onAt: (at: string) => void;
  onEdit: () => void;
  onRemoveTicket: (id: number) => void;
}) {
  const w = data.window;
  const p = data.plan;
  const tz = w.timezone;
  return (
    <section className="card card-pad stack grow-3" aria-labelledby="plan-title">
      <div className="inline" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
        <div className="stack" style={{ gap: 4 }}>
          <h2 id="plan-title" style={{ margin: 0 }}>
            {w.name}
          </h2>
          <span className="faint" style={{ fontSize: 13 }}>
            {w.kind_label} · {w.schedule} · {scopeText(w)}
          </span>
        </div>
        <div className="inline">
          <button type="button" className="btn btn-sm btn-ghost icon-btn" aria-label="Предыдущая дата" disabled={!data.prev} onClick={() => data.prev && onAt(data.prev)}>
            <ChevronLeft size={15} />
          </button>
          <span className="mono" style={{ fontSize: 13 }}>
            {p ? fmtRange(p.occurrence.start, p.occurrence.end, tz) : "—"}
          </span>
          <button type="button" className="btn btn-sm btn-ghost icon-btn" aria-label="Следующая дата" disabled={!data.next} onClick={() => data.next && onAt(data.next)}>
            <ChevronRight size={15} />
          </button>
          {canEdit && (
            <button type="button" className="btn btn-sm" onClick={onEdit}>
              <Pencil size={15} aria-hidden="true" /> Изменить
            </button>
          )}
        </div>
      </div>
      {w.note && <p className="muted" style={{ margin: 0 }}>{w.note}</p>}
      {!p ? (
        <Empty title="У окна нет дат" icon={<CalendarClock size={28} />}>
          Разовое окно прошло или срок действия повторяющегося закончился.
        </Empty>
      ) : (
        <>
          {p.occurrence.cancelled && (
            <div className="alert alert-danger" role="status">
              <Ban size={15} aria-hidden="true" />
              <span>
                Эта дата выпадает: {p.occurrence.blackouts.map((b) => `блэкаут «${b.name}»`).join(", ")}. Работы в окне не проводятся.
              </span>
            </div>
          )}
          {!p.occurrence.cancelled && p.occurrence.blocked_hosts && p.occurrence.blocked_hosts.length > 0 && (
            <div className="alert alert-warn" role="status">
              <Ban size={15} aria-hidden="true" />
              <span>
                Блэкаут {p.occurrence.blackouts.map((b) => `«${b.name}»`).join(", ")} закрывает хосты:{" "}
                <span className="mono">{p.occurrence.blocked_hosts.join(", ")}</span>
              </span>
            </div>
          )}
          <div className="plan-hero">
            <div className="stack" style={{ gap: 6, flex: "1 1 260px" }}>
              <div className="inline" style={{ gap: "var(--s1) var(--s2)", alignItems: "baseline" }}>
                <span className="hero-number num">{fmtNumber(p.occurrence.cancelled ? 0 : p.will_close)}</span>
                <span className="hero2-title">
                  закроет {plural(p.occurrence.cancelled ? 0 : p.will_close, ["уязвимость", "уязвимости", "уязвимостей"])}
                </span>
              </div>
              <StackBar counts={p.will_close_by_severity} />
            </div>
            <div className="plan-facts">
              <div>
                <span className="faint">Заявок</span>
                <b className="num">{fmtNumber(p.items.length)}</b>
              </div>
              <div>
                <span className="faint">Хостов</span>
                <b className="num">{fmtNumber(p.hosts)}</b>
              </div>
              <div>
                <span className="faint">Перезагрузок</span>
                <b className="num">{fmtNumber(p.reboots)}</b>
              </div>
              <div>
                <span className="faint">Занято</span>
                <b className="num" style={{ color: p.planned_minutes > p.window_minutes ? "var(--danger)" : undefined }}>
                  {fmtMinutes(p.planned_minutes)} из {fmtMinutes(p.window_minutes)}
                </b>
              </div>
            </div>
          </div>
          {p.overflow_tickets > 0 && (
            <div className="alert alert-warn" role="status">
              <span>
                Не помещаются в окно: {fmtNumber(p.overflow_tickets)} {plural(p.overflow_tickets, ["заявка", "заявки", "заявок"])} ({fmtNumber(p.overflow_vulns)}{" "}
                {plural(p.overflow_vulns, ["уязвимость", "уязвимости", "уязвимостей"])}) — в итог не входят. Перенесите их в другое окно или увеличьте окно.
              </span>
            </div>
          )}
          {p.items.length === 0 ? (
            <Empty title="В окне пока нет заявок" icon={<ListPlus size={28} />}>
              Отметьте заявки в разделе «Заявки» и нажмите «В окно» или поставьте заявку в окно из её карточки.
            </Empty>
          ) : (
            <>
              <Timeline plan={p} tz={tz} />
              <span className="faint" style={{ fontSize: 12.5 }}>
                Длительность — оценка по виду заявки: хост-«канарейка», затем партии по 10 % хостов;{" "}
                <RotateCcw size={12} aria-hidden="true" style={{ verticalAlign: "-2px" }} /> — с перезагрузкой. Время — {tz}.
              </span>
              {canPlace && (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Заявка</th>
                        <th>Время</th>
                        <th className="num">Уязвимостей</th>
                        <th>Вне плана</th>
                        <th aria-label="Действия" />
                      </tr>
                    </thead>
                    <tbody>
                      {p.items.map((i) => (
                        <tr key={i.ticket_id}>
                          <td>
                            <Link to={`/tickets/${i.ticket_id}`}>№{i.ticket_id}</Link>
                          </td>
                          <td className="mono" style={{ whiteSpace: "nowrap" }}>
                            {i.start ? `${fmtZoned(i.start, tz, false)}–${fmtZoned(i.end, tz, false)}` : "—"}
                          </td>
                          <td className="num">{fmtNumber(i.vulns)}</td>
                          <td className="faint" style={{ fontSize: 12.5 }}>
                            {i.skipped_hosts.length ? i.skipped_hosts.map((s) => `${s.host} (${s.reason})`).join(", ") : "—"}
                          </td>
                          <td style={{ textAlign: "right" }}>
                            <button type="button" className="btn btn-sm btn-ghost" onClick={() => onRemoveTicket(i.ticket_id)}>
                              <X size={15} aria-hidden="true" /> Снять
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
          <div className="inline">
            <Link className="btn btn-sm" to={`/tickets?window=${w.id}`}>
              Заявки окна
            </Link>
            {canPlace && w.is_active && (
              <Link className="btn btn-sm" to="/tickets?window=none">
                <ListPlus size={15} aria-hidden="true" /> Добавить заявки
              </Link>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Calendar({ items, windows, onPick }: { items: CalendarItem[]; windows: WindowOut[]; onPick: (c: CalendarItem) => void }) {
  const tzOf = (id: number) => windows.find((w) => w.id === id)?.timezone ?? "Europe/Moscow";
  return (
    <section className="card card-pad stack" aria-labelledby="cal-title">
      <h2 id="cal-title" style={{ margin: 0 }}>
        Ближайшие 4 недели
      </h2>
      {items.length === 0 ? (
        <Empty title="Дат нет">Создайте окно обслуживания — его даты появятся здесь.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Когда</th>
                <th>Окно</th>
                <th className="num">Заявок</th>
                <th className="num">Закроет</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr
                  key={`${c.window_id}-${c.start}`}
                  className={c.kind === "blackout" ? "" : "clickable"}
                  onClick={() => c.kind !== "blackout" && onPick(c)}
                  style={c.cancelled ? { textDecoration: "line-through", color: "var(--text-3)" } : undefined}
                >
                  <td className="mono" style={{ whiteSpace: "nowrap" }}>
                    {fmtRange(c.start, c.end, tzOf(c.window_id))}
                  </td>
                  <td>
                    {c.kind === "blackout" ? (
                      <span className="pill pill-danger">блэкаут · {c.window_name}</span>
                    ) : (
                      <>
                        {c.window_name}
                        {c.cancelled && <span className="faint"> — выпадает</span>}
                      </>
                    )}
                  </td>
                  <td className="num">{c.kind === "blackout" ? "" : fmtNumber(c.tickets ?? 0)}</td>
                  <td className="num">{c.kind === "blackout" ? "" : fmtNumber(c.will_close ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function WindowsPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const [params, setParams] = useSearchParams();
  const list = useAsync(() => api.windows(projectId), [projectId]);
  const cal = useAsync(() => api.calendar(projectId), [projectId]);
  const [form, setForm] = useState<{ kind?: WindowKind; edit?: WindowOut } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canEdit = has("windows_manage");
  const canPlace = has("ticket_assign");

  const all = list.data ?? [];
  const work = all.filter((w) => w.kind !== "blackout");
  const blackouts = all.filter((w) => w.kind === "blackout");
  const selectedId = Number(params.get("window")) || work.find((w) => w.is_active && w.next)?.id || work[0]?.id || null;
  const at = params.get("at") ?? undefined;
  const plan = useAsync(() => api.windowPlan(selectedId!, at), [selectedId, at], !!selectedId);

  useEffect(() => setError(null), [selectedId]);

  const select = (id: number, when?: string) => {
    const next = new URLSearchParams(params);
    next.set("window", String(id));
    if (when) next.set("at", when);
    else next.delete("at");
    setParams(next, { replace: true });
  };
  const reloadAll = () => {
    void list.reload();
    void cal.reload();
    if (selectedId) void plan.reload();
  };
  const removeTicket = async (id: number) => {
    setError(null);
    try {
      await api.placeInWindow(id, null);
      reloadAll();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Окна и план</h1>
        </div>
        {canEdit && (
          <div className="actions">
            <button type="button" className="btn" onClick={() => setForm({ kind: "blackout" })}>
              <Ban size={15} aria-hidden="true" /> Блэкаут
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setForm({ kind: "recurring" })}>
              <Plus size={15} aria-hidden="true" /> Новое окно
            </button>
          </div>
        )}
      </div>
      {list.error && <ErrorAlert error={list.error} onRetry={() => void list.reload()} />}
      {error && <ErrorAlert error={error} />}
      {list.loading && !list.data && <Loading />}
      {list.data && all.length === 0 && (
        <div className="card">
          <Empty title="Окон обслуживания пока нет" icon={<CalendarClock size={28} />}>
            {canEdit
              ? "Создайте окно — разовое или повторяющееся («вторник 22:00–02:00»). Блэкаут запрещает работы на время праздников или закрытия периода."
              : "Окна настраивает руководитель работ."}
          </Empty>
        </div>
      )}
      {list.data && all.length > 0 && (
        <div className="row">
          <section className="card card-pad stack grow-1" aria-labelledby="win-list" style={{ alignSelf: "flex-start" }}>
            <h2 id="win-list" style={{ margin: 0 }}>
              Окна
            </h2>
            {work.length === 0 && <span className="faint">Рабочих окон нет — только блэкауты.</span>}
            <div className="window-list">
              {work.map((w) => (
                <WindowRow key={w.id} w={w} selected={w.id === selectedId} onSelect={() => select(w.id)} />
              ))}
            </div>
            {blackouts.length > 0 && (
              <>
                <h3 className="faint" style={{ margin: "var(--s2) 0 0", fontSize: 13 }}>
                  Блэкауты
                </h3>
                <div className="window-list">
                  {blackouts.map((w) => (
                    <WindowRow key={w.id} w={w} selected={false} onSelect={() => canEdit && setForm({ edit: w })} />
                  ))}
                </div>
              </>
            )}
          </section>
          {selectedId && (
            <>
              {plan.error && <ErrorAlert error={plan.error} onRetry={() => void plan.reload()} />}
              {plan.loading && !plan.data && <Loading />}
              {plan.data && (
                <PlanPanel
                  data={plan.data}
                  canEdit={canEdit}
                  canPlace={canPlace}
                  onAt={(when) => select(plan.data!.window.id, when)}
                  onEdit={() => setForm({ edit: plan.data!.window })}
                  onRemoveTicket={(id) => void removeTicket(id)}
                />
              )}
            </>
          )}
        </div>
      )}
      {cal.data && all.length > 0 && <Calendar items={cal.data.items} windows={all} onPick={(c) => select(c.window_id, c.start)} />}
      {form && (
        <WindowFormModal
          projectId={projectId}
          initial={form.edit}
          kind={form.kind}
          onClose={() => setForm(null)}
          onSaved={(w) => {
            setForm(null);
            if (w && w.kind !== "blackout") select(w.id);
            else if (!w && form.edit?.id === selectedId) setParams(new URLSearchParams(), { replace: true });
            reloadAll();
          }}
        />
      )}
    </>
  );
}
