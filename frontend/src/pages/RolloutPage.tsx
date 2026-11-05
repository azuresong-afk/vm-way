import { Fragment, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  Ban,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  FlaskConical,
  Loader2,
  OctagonX,
  Play,
  Power,
  ShieldCheck,
  X,
} from "lucide-react";
import { api } from "../api/client";
import type { RolloutHostOut, RolloutOut, RolloutStage, RolloutStepOut, StageState } from "../api/types";
import { ErrorAlert, Empty, Loading, Modal } from "../components/ui";
import { fmtDate, fmtMs, fmtNumber, plural } from "../lib/format";
import { OUTCOME_LABEL, OUTCOME_PILL, ROLLOUT_HOST_PILL, ROLLOUT_STATUS_PILL, STAGE_LABEL } from "../lib/labels";
import { useAsync, useInterval } from "../lib/useAsync";

const LIVE = new Set(["dry_run", "running"]);

function StageIcon({ state }: { state: StageState }) {
  if (state === "done") return <Check size={14} aria-hidden="true" />;
  if (state === "running") return <Loader2 size={14} aria-hidden="true" className="spin" />;
  if (state === "failed") return <X size={14} aria-hidden="true" />;
  if (state === "skipped") return <Ban size={14} aria-hidden="true" />;
  return <CircleDashed size={14} aria-hidden="true" />;
}

/** Этапы: пробный прогон → утверждение → канарейка → партии → проверка. */
function Stages({ stages }: { stages: RolloutStage[] }) {
  return (
    <ol className="stepper" aria-label="Этапы раскатки">
      {stages.map((s) => (
        <li key={s.key} className={`step step-${s.state}`}>
          <span className="step-dot">
            <StageIcon state={s.state} />
          </span>
          <span className="step-text">
            <b>{s.label}</b>
            <span className="faint">
              {STAGE_LABEL[s.state]}
              {s.key === "canary" && s.hosts?.length ? ` · ${s.hosts[0]}` : ""}
            </span>
            {s.key === "batches" && (s.batches?.length ?? 0) > 0 && (
              <span className="step-batches">
                {s.batches!.map((b) => (
                  <i key={b.stage} className={`batch batch-${b.state}`} title={`Партия ${b.stage}: ${b.hosts.join(", ")} — ${STAGE_LABEL[b.state]}`} />
                ))}
              </span>
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}

function Versions({ h }: { h: RolloutHostOut }) {
  const names = Array.from(new Set([...Object.keys(h.versions_before), ...Object.keys(h.versions_after)]));
  if (!names.length) return <span className="faint">—</span>;
  return (
    <span className="versions">
      {names.map((n) => {
        const a = h.versions_before[n];
        const b = h.versions_after[n];
        return (
          <span key={n} className="mono">
            {names.length > 1 && <span className="faint">{n}: </span>}
            {a ?? <span className="faint">нет</span>}
            {b !== undefined && b !== a && (
              <>
                {" "}
                → <b>{b ?? "нет"}</b>
              </>
            )}
          </span>
        );
      })}
      {h.kernel_after && h.kernel_after !== h.kernel_before && (
        <span className="mono faint">
          ядро {h.kernel_before} → {h.kernel_after}
        </span>
      )}
    </span>
  );
}

function DryPlan({ h }: { h: RolloutHostOut }) {
  if (h.dry_status !== "ok") return h.reason ? <span>{h.reason}</span> : <span className="faint">—</span>;
  return (
    <span className="versions">
      {h.dry_plan.slice(0, 6).map((p) => (
        <span key={p.package} className="mono">
          {p.package} {p.from && <span className="faint">{p.from}</span>} → <b>{p.to || "новее"}</b>
        </span>
      ))}
      {h.dry_plan.length > 6 && <span className="faint">и ещё {h.dry_plan.length - 6}</span>}
      {h.dry_note && <span className="faint">{h.dry_note}</span>}
    </span>
  );
}

function HostLog({ rollout, h, live }: { rollout: number; h: RolloutHostOut; live: boolean }) {
  const log = useAsync<RolloutStepOut[]>(() => api.rolloutSteps(rollout, h.id), [rollout, h.id]);
  useInterval(() => void log.reload(), 2000, live);
  if (log.error) return <ErrorAlert error={log.error} onRetry={() => void log.reload()} />;
  if (!log.data) return <Loading />;
  if (!log.data.length) return <span className="faint">Команд пока не было.</span>;
  return (
    <div className="host-log">
      {h.rollback.length > 0 && (
        <div className="alert alert-info">
          <span>
            Откат к версии «до» (не выполняется автоматически): <span className="mono">{h.rollback.join("; ")}</span>
          </span>
        </div>
      )}
      {log.data.map((s) => (
        <details key={s.id} className={`log-step ${s.ok ? "" : "is-bad"}`} open={!s.ok}>
          <summary>
            <span className="log-phase">{s.phase === "dry_run" ? "пробный" : "запуск"}</span>
            <b>{s.label}</b>
            <span className="mono log-cmd">{s.command}</span>
            <span className="log-meta">
              {s.returncode !== null ? `код ${s.returncode}` : s.ok ? "" : "ошибка"} · {fmtMs(s.duration_ms)}
            </span>
          </summary>
          {s.stdout && <pre className="mono log-out">{s.stdout}</pre>}
          {s.stderr && <pre className="mono log-out log-err">{s.stderr}</pre>}
          {!s.stdout && !s.stderr && <span className="faint">вывода нет</span>}
        </details>
      ))}
    </div>
  );
}

function stageName(h: RolloutHostOut): string {
  if (h.stage === null) return h.canary ? "канарейка" : "—";
  return h.stage === 0 ? "канарейка" : `партия ${h.stage}`;
}

function Hosts({ r }: { r: RolloutOut }) {
  const [open, setOpen] = useState<number | null>(null);
  const hosts = r.hosts ?? [];
  const executed = !!r.started_at;
  return (
    <section className="card" aria-labelledby="rh-head">
      <div className="card-head">
        <h2 id="rh-head">Хосты</h2>
        <span className="count">
          {fmtNumber(hosts.length)} {plural(hosts.length, ["хост", "хоста", "хостов"])}
        </span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th aria-label="Журнал" />
              <th>Хост</th>
              <th>Этап</th>
              <th>Статус</th>
              <th>{executed ? "Версии «до → после»" : "Что изменится"}</th>
              <th className="right">Время</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => {
              const isOpen = open === h.id;
              const steps = r.step_counts?.[String(h.id)] ?? 0;
              return (
                <Fragment key={h.id}>
                  <tr className={steps ? "row-click" : undefined} onClick={() => steps && setOpen(isOpen ? null : h.id)}>
                    <td style={{ width: 28 }}>
                      {steps > 0 && (
                        <button
                          type="button"
                          className="btn btn-ghost icon-btn btn-sm"
                          aria-expanded={isOpen}
                          aria-label={`Журнал ${h.host}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            setOpen(isOpen ? null : h.id);
                          }}
                        >
                          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </button>
                      )}
                    </td>
                    <td className="nowrap">
                      <span className="mono">{h.host}</span>
                      {h.credential && <div className="faint">{h.credential.name}</div>}
                    </td>
                    <td className="nowrap">{stageName(h)}</td>
                    <td>
                      <span className={`pill ${ROLLOUT_HOST_PILL[h.status]}`}>{h.status_label}</span>
                      {h.rebooted && <div className="faint">перезагружен</div>}
                      {executed && h.reason && <div className="faint" style={{ maxWidth: 280 }}>{h.reason}</div>}
                    </td>
                    <td style={{ minWidth: 220 }}>{executed && h.status !== "skipped" ? <Versions h={h} /> : <DryPlan h={h} />}</td>
                    <td className="right nowrap">{fmtMs(h.duration_ms)}</td>
                  </tr>
                  {isOpen && (
                    <tr className="row-detail">
                      <td colSpan={6}>
                        <HostLog rollout={r.id} h={h} live={LIVE.has(r.status)} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Params({ r }: { r: RolloutOut }) {
  const who = (u: RolloutOut["prepared_by"]) => u?.display_name ?? "—";
  return (
    <section className="card card-pad stack" aria-labelledby="rp-head">
      <h2 id="rp-head">Параметры</h2>
      <dl className="kv">
        <dt>Заявка</dt>
        <dd>{r.ticket ? <Link to={`/tickets/${r.ticket.id}`}>№{r.ticket.id} {r.ticket.title}</Link> : "—"}</dd>
        <dt>Шаблон</dt>
        <dd>{r.template_label}</dd>
        {r.manager && (
          <>
            <dt>Менеджер</dt>
            <dd className="mono">{r.manager}</dd>
          </>
        )}
        {r.packages.length > 0 && (
          <>
            <dt>Пакеты</dt>
            <dd>
              {r.packages.map((p) => (
                <span key={p} className="tag tag-muted mono">
                  {p}
                </span>
              ))}
              {r.fixed_version && <span className="faint">не ниже {r.fixed_version}</span>}
            </dd>
          </>
        )}
        {r.service && (
          <>
            <dt>Служба</dt>
            <dd className="mono">{r.service}</dd>
          </>
        )}
        {r.command && (
          <>
            <dt>Команда</dt>
            <dd className="mono">{r.command}</dd>
          </>
        )}
        <dt>Окно</dt>
        <dd>
          {r.outside_window ? (
            <span>
              вне окна <span className="faint">— {r.outside_window_reason}</span>
            </span>
          ) : r.window ? (
            <Link to={`/windows?window=${r.window.id}`}>{r.window.name}</Link>
          ) : (
            <span className="faint">не задано</span>
          )}
        </dd>
        <dt>Порционность</dt>
        <dd>
          канарейка <span className="mono">{r.canary_host}</span>, партии по {r.batch_percent} %, стоп при ошибках &gt; {r.failure_threshold} %
        </dd>
        <dt>Перезагрузка</dt>
        <dd>{r.decided_at ? (r.allow_reboot ? "разрешена" : "не разрешена") : <span className="faint">решает руководитель</span>}</dd>
        <dt>Подготовил</dt>
        <dd>
          {who(r.prepared_by)} <span className="faint">{fmtDate(r.created_at)}</span>
        </dd>
        <dt>Пробный прогон</dt>
        <dd>{r.dry_run_at ? <>{who(r.dry_run_by)} <span className="faint">{fmtDate(r.dry_run_at)}</span></> : <span className="faint">не было</span>}</dd>
        <dt>{r.status === "rejected" ? "Отклонил" : "Утвердил"}</dt>
        <dd>
          {r.decided_at ? (
            <>
              {who(r.decided_by)} <span className="faint">{fmtDate(r.decided_at)}</span>
              {r.decision_note && <span className="faint">«{r.decision_note}»</span>}
            </>
          ) : (
            <span className="faint">—</span>
          )}
        </dd>
        <dt>Запустил</dt>
        <dd>{r.started_at ? <>{who(r.started_by)} <span className="faint">{fmtDate(r.started_at)}</span></> : <span className="faint">—</span>}</dd>
        {r.stopped_by && (
          <>
            <dt>Остановил</dt>
            <dd>
              {who(r.stopped_by)} <span className="faint">— {r.stop_reason}</span>
            </dd>
          </>
        )}
        {r.note && (
          <>
            <dt>Комментарий</dt>
            <dd>{r.note}</dd>
          </>
        )}
      </dl>
      {(r.verifications?.length ?? 0) > 0 && (
        <div className="stack" style={{ gap: 6 }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>Повторная проверка</h3>
          {r.verifications!.map((v) => {
            const o = v.result?.outcome;
            return (
              <div key={v.id} className="list-row">
                <span style={{ flex: 1 }}>
                  {v.scanner_run_id ? `Прогон №${v.scanner_run_id} «Сканера»` : "Прогон ещё не запущен"} ·{" "}
                  <span className="faint">{v.targets.length} хост(ов)</span>
                </span>
                <span className={`pill ${o ? OUTCOME_PILL[o] : "pill-info pill-running"}`}>{o ? OUTCOME_LABEL[o] : "идёт"}</span>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

type Dialog = "approve" | "reject" | "stop" | "cancel" | null;

function ApproveModal({ r, onClose, onDone }: { r: RolloutOut; onClose: () => void; onDone: (r: RolloutOut) => void }) {
  const needsReboot = r.template === "kernel" || (r.hosts ?? []).some((h) => h.dry_plan.some((p) => p.package.startsWith("linux-image") || p.package === "kernel"));
  const [reboot, setReboot] = useState(needsReboot);
  const [outside, setOutside] = useState(!r.window);
  const [reason, setReason] = useState("");
  const [ack, setAck] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = r.hosts?.filter((h) => h.dry_status === "ok").length ?? 0;
  const bad = r.hosts?.filter((h) => h.dry_status === "failed").length ?? 0;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(await api.rolloutApprove(r.id, { allow_reboot: reboot, outside_window: outside, outside_window_reason: reason, custom_ack: ack, note }));
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Утвердить раскатку №${r.id}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || (outside && reason.trim().length < 3) || (r.template === "custom" && !ack)}
            onClick={() => void submit()}
          >
            <ShieldCheck size={15} aria-hidden="true" /> Утвердить
          </button>
        </>
      }
    >
      <span className="muted">
        Пробный прогон пройден на {ok} {plural(ok, ["хосте", "хостах", "хостах"])}
        {bad ? `, не прошёл на ${bad} — эти хосты в раскатку не попадут` : ""}. Запустит раскатку исполнитель — не вы.
      </span>
      <label className="check">
        <input type="checkbox" checked={reboot} onChange={(e) => setReboot(e.target.checked)} />
        <span>
          <b>Разрешить перезагрузку</b>
          <small>
            {needsReboot ? "Обновление ядра заработает только после перезагрузки. " : ""}Без разрешения хост, которому нужна перезагрузка, останется «ждёт
            перезагрузки».
          </small>
        </span>
      </label>
      <label className="check">
        <input type="checkbox" checked={outside} onChange={(e) => setOutside(e.target.checked)} disabled={!r.window} />
        <span>
          <b>Запуск вне окна обслуживания</b>
          <small>{r.window ? `Иначе — только пока открыто окно «${r.window.name}».` : "У раскатки нет окна — запуск возможен только так."} Блэкаут запрещает запуск в любом случае.</small>
        </span>
      </label>
      {outside && (
        <label className="field">
          <span>Причина запуска вне окна</span>
          <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} placeholder="Например: срочное исправление, согласовано с заказчиком" />
        </label>
      )}
      {r.template === "custom" && (
        <label className="check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>
            <b>Утверждаю произвольную команду</b>
            <small className="mono">{r.command}</small>
          </span>
        </label>
      )}
      <label className="field">
        <span>Комментарий (необязательно)</span>
        <input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} />
      </label>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

function ReasonModal({
  title,
  text,
  label,
  danger,
  optional,
  onClose,
  onSubmit,
}: {
  title: string;
  text: string;
  label: string;
  danger?: boolean;
  optional?: boolean;
  onClose: () => void;
  onSubmit: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(reason.trim());
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={busy || (!optional && reason.trim().length < 3)} onClick={() => void submit()}>
            {label}
          </button>
        </>
      }
    >
      <span className="muted">{text}</span>
      <label className="field">
        <span>Причина{optional ? " (необязательно)" : ""}</span>
        <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 70 }} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
      </label>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

export function RolloutPage() {
  const { id } = useParams();
  const rid = Number(id);
  const valid = Number.isInteger(rid) && rid > 0;
  const q = useAsync<RolloutOut>(() => api.rollout(rid), [rid], valid);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const r = q.data;
  const live = !!r && (LIVE.has(r.status) || (r.verifications ?? []).some((v) => v.status === "requested" || v.status === "running"));
  useInterval(() => void q.reload(), 2000, live);

  if (!valid) return <div className="card"><Empty title="Раскатка не найдена" /></div>;
  if (q.error && !r) return <ErrorAlert error={q.error} onRetry={() => void q.reload()} />;
  if (!r) return <Loading />;
  const can = r.can!;
  const act = async (fn: () => Promise<RolloutOut>) => {
    setBusy(true);
    setError(null);
    try {
      q.setData(await fn());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const done = (x: RolloutOut) => {
    setDialog(null);
    q.setData(x);
  };
  const waiting = r.counts.reboot_pending ?? 0;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to="/rollouts">Раскатки</Link> <span aria-hidden="true">/</span> <span>№{r.id}</span>
          </span>
          <h1>{r.title}</h1>
          <span className="inline" style={{ gap: 8, marginTop: 4 }}>
            <span className={`pill ${ROLLOUT_STATUS_PILL[r.status]}`}>{r.stop_requested && r.status === "running" ? "Останавливается" : r.status_label}</span>
            <span className="pill pill-muted">{r.template_label}</span>
            {r.allow_reboot && (
              <span className="pill pill-warn">
                <Power size={12} aria-hidden="true" /> перезагрузка разрешена
              </span>
            )}
          </span>
        </div>
        <div className="actions">
          {can.cancel && (
            <button type="button" className="btn" onClick={() => setDialog("cancel")} disabled={busy}>
              Отменить
            </button>
          )}
          {can.reject && (
            <button type="button" className="btn" onClick={() => setDialog("reject")} disabled={busy}>
              Отклонить
            </button>
          )}
          {can.dry_run && (
            <button type="button" className={`btn ${r.status === "draft" ? "btn-primary" : ""}`} onClick={() => void act(() => api.rolloutDryRun(r.id))} disabled={busy}>
              <FlaskConical size={15} aria-hidden="true" /> {r.dry_run_at ? "Повторить пробный прогон" : "Пробный прогон"}
            </button>
          )}
          {can.approve && (
            <button type="button" className="btn btn-primary" onClick={() => setDialog("approve")} disabled={busy}>
              <ShieldCheck size={15} aria-hidden="true" /> Утвердить
            </button>
          )}
          {can.start && (
            <button type="button" className="btn btn-primary" onClick={() => void act(() => api.rolloutStart(r.id))} disabled={busy}>
              <Play size={15} aria-hidden="true" /> Запустить
            </button>
          )}
          {can.stop && (
            <button type="button" className="btn btn-danger" onClick={() => setDialog("stop")} disabled={busy}>
              <OctagonX size={15} aria-hidden="true" /> Аварийный стоп
            </button>
          )}
        </div>
      </div>
      {error && <ErrorAlert error={error} />}
      {r.stages && (
        <section className="card card-pad">
          <Stages stages={r.stages} />
        </section>
      )}
      {r.error && (
        <div className={`alert ${r.status === "done" ? "alert-warn" : "alert-danger"}`}>
          <AlertTriangle size={16} aria-hidden="true" />
          <span>{r.error}</span>
        </div>
      )}
      {r.status === "pending_approval" && !can.approve && (
        <div className="alert alert-info">
          <span>Ждёт утверждения руководителем. Утверждает не тот, кто готовил раскатку или делал пробный прогон.</span>
        </div>
      )}
      {r.status === "approved" && !can.start && (
        <div className="alert alert-info">
          <span>Утверждена. Запускает исполнитель с правом «Запуск раскатки на хостах» — не утвердивший.</span>
        </div>
      )}
      {r.stop_requested && r.status === "running" && (
        <div className="alert alert-warn">
          <OctagonX size={16} aria-hidden="true" />
          <span>Аварийный стоп: команды, которые уже идут на хостах, доработают, новые хосты и перезагрузки не начнутся.</span>
        </div>
      )}
      {waiting > 0 && (
        <div className="alert alert-warn">
          <Power size={16} aria-hidden="true" />
          <span>
            {waiting} {plural(waiting, ["хост ждёт", "хоста ждут", "хостов ждут"])} перезагрузки: при утверждении она не была разрешена. Повторная проверка для
            них не запускалась.
          </span>
        </div>
      )}
      <div className="row">
        <div className="grow-3 stack" style={{ gap: "var(--s3)" }}>
          <Hosts r={r} />
        </div>
        <div className="grow-2 stack" style={{ gap: "var(--s3)" }}>
          <Params r={r} />
        </div>
      </div>
      {dialog === "approve" && <ApproveModal r={r} onClose={() => setDialog(null)} onDone={done} />}
      {dialog === "reject" && (
        <ReasonModal
          title={`Отклонить раскатку №${r.id}`}
          text="Раскатка закроется без изменений на хостах. Причина попадёт в историю заявки и журнал аудита."
          label="Отклонить"
          danger
          onClose={() => setDialog(null)}
          onSubmit={async (why) => done(await api.rolloutReject(r.id, why))}
        />
      )}
      {dialog === "cancel" && (
        <ReasonModal
          title={`Отменить раскатку №${r.id}`}
          text="Раскатка закроется без изменений на хостах."
          label="Отменить раскатку"
          optional
          onClose={() => setDialog(null)}
          onSubmit={async (why) => done(await api.rolloutCancel(r.id, why))}
        />
      )}
      {dialog === "stop" && (
        <ReasonModal
          title={`Аварийный стоп раскатки №${r.id}`}
          text="Новые хосты и перезагрузки не начнутся. Команда, которая уже выполняется на хосте, доработает до конца: обрыв менеджера пакетов посреди установки ломает систему."
          label="Остановить"
          danger
          onClose={() => setDialog(null)}
          onSubmit={async (why) => done(await api.rolloutStop(r.id, why))}
        />
      )}
    </>
  );
}
