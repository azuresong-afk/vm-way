// Исключения (задача 2.5): форма оформления, карточка исключения с действиями, отметка в «Сканере».

import { useState } from "react";
import { Link } from "react-router-dom";
import { CalendarPlus, Check, RefreshCw, ShieldOff, Undo2, X } from "lucide-react";
import { api } from "../api/client";
import type { ExceptionKind, ExceptionOut, TicketDetail } from "../api/types";
import { fmtDate, fmtDay, plural } from "../lib/format";
import { EXCEPTION_STATUS_PILL, STATUS_LABEL } from "../lib/labels";
import { notifyJobs } from "../lib/jobs";
import { reviewLeft } from "../lib/exceptions";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Modal } from "./ui";

const TEXTAREA = { fontFamily: "var(--font)", minHeight: 89 } as const;

function useSubmit(onDone: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

export function ReviewDate({ ex }: { ex: ExceptionOut }) {
  if (!ex.review_on) return <span className="faint">без даты</span>;
  const left = reviewLeft(ex);
  return (
    <span className="nowrap" style={{ display: "inline-flex", flexDirection: "column" }}>
      <span>{fmtDay(ex.review_on)}</span>
      {left && (
        <span className="faint" style={{ fontSize: 12, color: ex.review_soon ? "var(--warn)" : undefined }}>
          {left}
        </span>
      )}
    </span>
  );
}

export function ExceptionPill({ ex }: { ex: ExceptionOut }) {
  return <span className={`pill ${EXCEPTION_STATUS_PILL[ex.status]}`}>{ex.status_label}</span>;
}

/** Оформить исключение по заявке: вид, обоснование, меры, утверждающий, дата пересмотра. */
export function RequestExceptionModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const meta = useAsync(() => api.exceptionMeta(t.project_id), [t.project_id]);
  const [kind, setKind] = useState<ExceptionKind>("risk_accepted");
  const [reason, setReason] = useState("");
  const [measures, setMeasures] = useState("");
  const [approver, setApprover] = useState<number | null>(null);
  const [review, setReview] = useState<string | null>(null);
  const [noReview, setNoReview] = useState(true);
  const [sync, setSync] = useState(true);
  const s = useSubmit(onDone);
  const m = meta.data;
  const reviewOn = review ?? m?.default_review_on ?? "";
  const risk = kind === "risk_accepted";
  const approverId = approver ?? (m?.approvers.length === 1 ? m.approvers[0].id : null);
  const effectiveReview = risk || !noReview ? reviewOn : null;
  const ok = reason.trim().length >= 10 && approverId !== null && (!risk || !!reviewOn);
  return (
    <Modal
      title={`Исключение для заявки №${t.id}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={s.busy || !ok}
            onClick={() =>
              void s.run(() =>
                api.createException(t.id, {
                  kind,
                  reason: reason.trim(),
                  measures: risk ? measures.trim() : "",
                  approver_id: approverId,
                  review_on: effectiveReview,
                  sync_scanner: !risk && !!m?.sync_available && sync,
                }),
              )
            }
          >
            {s.busy ? "Отправка…" : "Отправить на утверждение"}
          </button>
        </>
      }
    >
      <div className="seg" role="radiogroup" aria-label="Вид исключения">
        <button type="button" role="radio" aria-checked={risk} onClick={() => setKind("risk_accepted")}>
          Принять риск
        </button>
        <button type="button" role="radio" aria-checked={!risk} onClick={() => setKind("false_positive")}>
          Ложное срабатывание
        </button>
      </div>
      <span className="muted">
        {risk
          ? "Уязвимость останется на хостах, заявка закроется без исправления до даты пересмотра. Когда дата наступит, заявка сама вернётся в работу, если исключение не продлят."
          : "«Сканер» ошибся: уязвимости на самом деле нет. Заявка закроется без повторной проверки."}{" "}
        Пока исключение ждёт утверждения, работа по заявке продолжается.
      </span>
      <label className="field">
        <span>Обоснование</span>
        <textarea
          className="textarea"
          style={TEXTAREA}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={4000}
          placeholder={risk ? "Почему риск допустим: сервер выводится, уязвимый компонент не используется…" : "Почему это не уязвимость: версия с бэкпортом, служба не запущена…"}
        />
        <small>Не короче 10 символов. Попадёт в историю заявки, журнал аудита{risk ? "" : " и, по желанию, в «Сканер»"}.</small>
      </label>
      {risk && (
        <label className="field">
          <span>Компенсирующие меры (необязательно)</span>
          <textarea
            className="textarea"
            style={{ ...TEXTAREA, minHeight: 64 }}
            value={measures}
            onChange={(e) => setMeasures(e.target.value)}
            maxLength={4000}
            placeholder="Порт закрыт на межсетевом экране, доступ только из сети администраторов…"
          />
        </label>
      )}
      <div className="row" style={{ gap: "var(--s2)" }}>
        <label className="field grow">
          <span>Утверждающий</span>
          <select
            className="select"
            value={approverId ?? ""}
            onChange={(e) => setApprover(e.target.value ? Number(e.target.value) : null)}
            disabled={meta.loading}
          >
            <option value="">— выберите —</option>
            {(m?.approvers ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name}
              </option>
            ))}
          </select>
          <small>Руководитель, кроме вас: исключение утверждает второй человек.</small>
        </label>
        <label className="field grow">
          <span>Дата пересмотра{risk ? "" : " (необязательно)"}</span>
          {!risk && (
            <label className="check" style={{ marginBottom: 4 }}>
              <input type="checkbox" checked={noReview} onChange={(e) => setNoReview(e.target.checked)} />
              <span>без даты пересмотра</span>
            </label>
          )}
          {(risk || !noReview) && (
            <input
              className="input"
              type="date"
              value={reviewOn}
              min={m?.min_review_on}
              max={m?.max_review_on}
              onChange={(e) => setReview(e.target.value)}
            />
          )}
          <small>Не дальше чем через год.</small>
        </label>
      </div>
      {!risk && m?.sync_available && (
        <label className="check">
          <input type="checkbox" checked={sync} onChange={(e) => setSync(e.target.checked)} />
          <span>
            <b>Отметить ложным срабатыванием в «Сканере»</b>
            <small>После утверждения уязвимости заявки будут отмечены и в «Сканере» (уйдут из «Что исправить»); снятие исключения снимет отметку.</small>
          </span>
        </label>
      )}
      {m && m.approvers.length === 0 && <ErrorAlert error="Некому утвердить: нужен ещё один пользователь с ролью руководителя." />}
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

type Act = "approve" | "reject" | "withdraw" | "revoke" | "extend";

const ACT: Record<Act, { title: string; label: string; reason: string; required: boolean; danger?: boolean }> = {
  approve: { title: "Утвердить исключение", label: "Утвердить", reason: "Комментарий (необязательно)", required: false },
  reject: { title: "Отклонить исключение", label: "Отклонить", reason: "Причина", required: true, danger: true },
  withdraw: { title: "Отозвать исключение", label: "Отозвать", reason: "Причина (необязательно)", required: false },
  revoke: { title: "Снять исключение", label: "Снять и вернуть в работу", reason: "Причина", required: true, danger: true },
  extend: { title: "Продлить исключение", label: "Продлить", reason: "Причина продления", required: true },
};

function ActModal({ ex, act, onClose, onDone }: { ex: ExceptionOut; act: Act; onClose: () => void; onDone: () => void }) {
  const meta = useAsync(() => api.exceptionMeta(ex.project_id), [ex.project_id], act === "extend");
  const [text, setText] = useState("");
  const [date, setDate] = useState<string | null>(null);
  const s = useSubmit(onDone);
  const c = ACT[act];
  const newDate = date ?? meta.data?.default_review_on ?? "";
  const call = () => {
    const r = text.trim();
    switch (act) {
      case "approve":
        return api.approveException(ex.id, r);
      case "reject":
        return api.rejectException(ex.id, r);
      case "withdraw":
        return api.withdrawException(ex.id, r);
      case "revoke":
        return api.revokeException(ex.id, r);
      case "extend":
        return api.extendException(ex.id, newDate, r);
    }
  };
  return (
    <Modal
      title={`${c.title} №${ex.id}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className={`btn ${c.danger ? "btn-danger" : "btn-primary"}`}
            disabled={s.busy || (c.required && text.trim().length < 3) || (act === "extend" && !newDate)}
            onClick={() =>
              void s.run(async () => {
                await call();
                notifyJobs();
              })
            }
          >
            {s.busy ? "Сохранение…" : c.label}
          </button>
        </>
      }
    >
      {act === "approve" && (
        <span className="muted">
          Заявка №{ex.ticket?.id} перейдёт в «{STATUS_LABEL[ex.kind]}»
          {ex.review_on ? ` до ${fmtDay(ex.review_on)}` : ""} и закроется без исправления.
          {ex.sync_scanner ? " Уязвимости будут отмечены ложными срабатываниями в «Сканере»." : ""}
        </span>
      )}
      {act === "revoke" && (
        <span className="muted">
          Заявка №{ex.ticket?.id} вернётся в работу.{ex.sync.marked?.length ? " Отметка ложного срабатывания в «Сканере» будет снята." : ""}
        </span>
      )}
      {act === "extend" && (
        <label className="field">
          <span>Новая дата пересмотра</span>
          <input
            className="input"
            type="date"
            value={newDate}
            min={meta.data?.min_review_on}
            max={meta.data?.max_review_on}
            onChange={(e) => setDate(e.target.value)}
          />
          <small>Сейчас — {ex.review_on ? fmtDay(ex.review_on) : "без даты"}. Не дальше чем через год от сегодня.</small>
        </label>
      )}
      <label className="field">
        <span>{c.reason}</span>
        <textarea className="textarea" style={TEXTAREA} value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} />
      </label>
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

const SYNC_STATE: Record<string, [string, string]> = {
  queued: ["выполняется", "pill-info pill-running"],
  done: ["выполнено", "pill-ok"],
  partial: ["частично", "pill-warn"],
  failed: ["ошибка", "pill-danger"],
  skipped: ["пропущено", "pill-muted"],
};

function SyncState({ ex }: { ex: ExceptionOut }) {
  const st = ex.sync.state;
  if (!ex.sync_scanner && !st) return <span className="faint">не отмечать</span>;
  if (!st) return <span className="faint">после утверждения</span>;
  const [label, pill] = SYNC_STATE[st] ?? [st, "pill-muted"];
  const verb = ex.sync.action === "unmark" ? "Снятие отметки" : "Отметка";
  return (
    <span style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <span className="inline" style={{ gap: 6 }}>
        <span className={`pill ${pill}`}>
          {verb}: {label}
        </span>
        {ex.sync.total !== undefined && st !== "queued" && (
          <span className="faint">
            {ex.sync.done ?? 0} из {ex.sync.total}
          </span>
        )}
      </span>
      {(ex.sync.errors ?? []).slice(0, 3).map((e, i) => (
        <span key={i} className="faint" style={{ fontSize: 12.5 }}>
          {e.host ? `${e.host} ${e.vuln}: ` : ""}
          {e.error}
        </span>
      ))}
    </span>
  );
}

/** Карточка исключения: сведения, продления, отметка в «Сканере» и действия по блоку `can`. */
export function ExceptionDetails({ ex, onChanged, showTicket }: { ex: ExceptionOut; onChanged: () => void; showTicket?: boolean }) {
  const [act, setAct] = useState<Act | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const can = ex.can;
  const resync = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.syncException(ex.id);
      notifyJobs();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack" style={{ gap: "var(--s2)" }}>
      <dl className="kv">
        {showTicket && ex.ticket && (
          <>
            <dt>Заявка</dt>
            <dd>
              <Link to={`/tickets/${ex.ticket.id}?project=${ex.project_id}`}>
                №{ex.ticket.id} {ex.ticket.title}
              </Link>
            </dd>
          </>
        )}
        <dt>Вид</dt>
        <dd>{ex.kind_label}</dd>
        <dt>Статус</dt>
        <dd>
          <ExceptionPill ex={ex} />
        </dd>
        <dt>Обоснование</dt>
        <dd style={{ whiteSpace: "pre-wrap" }}>{ex.reason}</dd>
        {ex.measures && (
          <>
            <dt>Компенсирующие меры</dt>
            <dd style={{ whiteSpace: "pre-wrap" }}>{ex.measures}</dd>
          </>
        )}
        <dt>Дата пересмотра</dt>
        <dd>
          <ReviewDate ex={ex} />
        </dd>
        <dt>Оформил</dt>
        <dd>
          {ex.requested_by?.display_name ?? "—"} · {fmtDate(ex.requested_at)}
        </dd>
        <dt>Утверждающий</dt>
        <dd>
          {ex.approver?.display_name ?? "—"}
          {ex.decided_at && (
            <span className="faint">
              {ex.status === "rejected" ? "отклонил" : "утвердил"} {fmtDate(ex.decided_at)}
            </span>
          )}
        </dd>
        {ex.decision_note && (
          <>
            <dt>{ex.status === "rejected" ? "Причина отказа" : "Комментарий"}</dt>
            <dd>{ex.decision_note}</dd>
          </>
        )}
        {ex.status === "active" && (
          <>
            <dt>Охват</dt>
            <dd>
              {ex.hosts.length} {plural(ex.hosts.length, ["хост", "хоста", "хостов"])}, {ex.vuln_count}{" "}
              {plural(ex.vuln_count, ["уязвимость", "уязвимости", "уязвимостей"])} на момент утверждения
              {ex.new_hosts.length > 0 && (
                <span className="pill pill-warn" title={ex.new_hosts.join(", ")}>
                  новых хостов: {ex.new_hosts.length}
                </span>
              )}
            </dd>
          </>
        )}
        {ex.ended_at && (
          <>
            <dt>{ex.status === "expired" ? "Истекло" : ex.status === "withdrawn" ? "Отозвано" : "Снято"}</dt>
            <dd>
              {fmtDate(ex.ended_at)}
              {ex.ended_by ? ` · ${ex.ended_by.display_name}` : " · система"}
              {ex.end_reason && <span className="faint">{ex.end_reason}</span>}
            </dd>
          </>
        )}
        {ex.kind === "false_positive" && (
          <>
            <dt>В «Сканере»</dt>
            <dd>
              <SyncState ex={ex} />
            </dd>
          </>
        )}
      </dl>
      {ex.extensions.length > 0 && (
        <div>
          <div className="faint" style={{ fontSize: 13, marginBottom: 4 }}>
            Продления
          </div>
          {ex.extensions.map((e, i) => (
            <div key={i} className="list-row" style={{ fontSize: 13 }}>
              <span style={{ flex: 1 }}>
                {e.from || "без даты"} → <b>{e.to}</b>: {e.reason}
              </span>
              <span className="faint nowrap">
                {e.by_name} · {fmtDate(e.at)}
              </span>
            </div>
          ))}
        </div>
      )}
      {can && Object.values(can).some(Boolean) && (
        <div className="inline" style={{ gap: 8 }}>
          {can.approve && (
            <button type="button" className="btn btn-primary btn-sm" onClick={() => setAct("approve")}>
              <Check size={15} aria-hidden="true" /> Утвердить
            </button>
          )}
          {can.reject && (
            <button type="button" className="btn btn-sm" onClick={() => setAct("reject")}>
              <X size={15} aria-hidden="true" /> Отклонить
            </button>
          )}
          {can.extend && (
            <button type="button" className="btn btn-sm" onClick={() => setAct("extend")}>
              <CalendarPlus size={15} aria-hidden="true" /> Продлить
            </button>
          )}
          {can.sync && (
            <button type="button" className="btn btn-sm" disabled={busy || ex.sync.state === "queued"} onClick={() => void resync()}>
              <RefreshCw size={15} aria-hidden="true" /> {ex.status === "active" ? "Отметить в «Сканере» ещё раз" : "Снять отметку ещё раз"}
            </button>
          )}
          {can.withdraw && (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setAct("withdraw")}>
              <Undo2 size={15} aria-hidden="true" /> Отозвать
            </button>
          )}
          {can.revoke && (
            <button type="button" className="btn btn-sm btn-danger" onClick={() => setAct("revoke")}>
              <ShieldOff size={15} aria-hidden="true" /> Снять исключение
            </button>
          )}
        </div>
      )}
      {error && <ErrorAlert error={error} />}
      {act && (
        <ActModal
          ex={ex}
          act={act}
          onClose={() => setAct(null)}
          onDone={() => {
            setAct(null);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

/** Блок «Исключение» в карточке заявки: открытое — подробно, прошлые — строками. */
export function TicketExceptions({ t, onChanged }: { t: TicketDetail; onChanged: () => void }) {
  const [showPast, setShowPast] = useState(false);
  if (!t.exceptions.length) return null;
  const open = t.exceptions.find((e) => e.status === "pending" || e.status === "active");
  const past = t.exceptions.filter((e) => e !== open);
  return (
    <section className="card card-pad stack" aria-labelledby="exc-head">
      <h2 id="exc-head">Исключение</h2>
      {open ? <ExceptionDetails ex={open} onChanged={onChanged} /> : <span className="faint">Действующего исключения нет.</span>}
      {past.length > 0 && (
        <div>
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => setShowPast((v) => !v)} aria-expanded={showPast}>
            {showPast ? "Скрыть" : "Показать"} прошлые ({past.length})
          </button>
          {showPast &&
            past.map((e) => (
              <div key={e.id} className="list-row" style={{ fontSize: 13, alignItems: "flex-start" }}>
                <span style={{ flex: 1, minWidth: 0 }}>
                  <b>{e.kind_label}</b> · {e.reason}
                  <span className="faint" style={{ display: "block" }}>
                    {e.requested_by?.display_name} · {fmtDate(e.requested_at)}
                    {e.end_reason || e.decision_note ? ` · ${e.end_reason || e.decision_note}` : ""}
                  </span>
                </span>
                <ExceptionPill ex={e} />
              </div>
            ))}
        </div>
      )}
    </section>
  );
}
