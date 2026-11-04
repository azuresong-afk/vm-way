import { useState } from "react";
import { Bell, BellOff, CheckCheck, Hand, ShieldOff, SlidersHorizontal, UserPlus, ArrowRightLeft } from "lucide-react";
import { api } from "../api/client";
import type { AssignableUser, Severity, TicketDetail, TicketStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useAsync } from "../lib/useAsync";
import { plural } from "../lib/format";
import { EXCEPTION_STATUSES, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, reasonRequired } from "../lib/labels";
import { notifyJobs } from "../lib/jobs";
import { ErrorAlert, HostStatusPill, Modal } from "./ui";

type Dialog = "assign" | "status" | "risk" | "override" | "verify" | null;

/** Выбор исполнителя с загрузкой: сколько открытых заявок проекта уже на человеке. */
export function AssigneeSelect({
  projectId,
  value,
  onChange,
  id,
}: {
  projectId: string;
  value: number | null;
  onChange: (v: number | null) => void;
  id?: string;
}) {
  const users = useAsync<AssignableUser[]>(() => api.assignable(projectId), [projectId]);
  return (
    <select
      id={id}
      className="select"
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      disabled={users.loading}
    >
      <option value="">— без исполнителя —</option>
      {(users.data ?? []).map((u) => (
        <option key={u.id} value={u.id}>
          {u.display_name}
          {u.open_tickets !== undefined ? ` · ${u.open_tickets} ${plural(u.open_tickets, ["открытая", "открытые", "открытых"])}` : ""}
        </option>
      ))}
    </select>
  );
}

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

function Footer({ onClose, busy, label, danger, disabled, onSubmit }: { onClose: () => void; busy: boolean; label: string; danger?: boolean; disabled?: boolean; onSubmit: () => void }) {
  return (
    <>
      <button type="button" className="btn" onClick={onClose}>
        Отмена
      </button>
      <button type="button" className={`btn ${danger ? "btn-danger" : "btn-primary"}`} onClick={onSubmit} disabled={busy || disabled}>
        {busy ? "Сохранение…" : label}
      </button>
    </>
  );
}

function AssignModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const [who, setWho] = useState<number | null>(t.assignee?.id ?? null);
  const s = useSubmit(onDone);
  return (
    <Modal
      title={`Назначить заявку №${t.id}`}
      onClose={onClose}
      footer={<Footer onClose={onClose} busy={s.busy} label="Назначить" onSubmit={() => void s.run(() => api.assign(t.id, who))} />}
    >
      <label className="field">
        <span>Исполнитель</span>
        <AssigneeSelect projectId={t.project_id} value={who} onChange={setWho} />
        <small>Назначить можно исполнителя или руководителя. Снятие исполнителя вернёт заявку в «Новая».</small>
      </label>
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

function StatusModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const options = t.can.statuses.filter((s) => !EXCEPTION_STATUSES.includes(s) || EXCEPTION_STATUSES.includes(t.status));
  const [to, setTo] = useState<TicketStatus | "">(options[0] ?? "");
  const [reason, setReason] = useState("");
  const s = useSubmit(onDone);
  const need = to !== "" && reasonRequired(t.status, to);
  return (
    <Modal
      title={`Перевести заявку №${t.id}`}
      onClose={onClose}
      footer={
        <Footer
          onClose={onClose}
          busy={s.busy}
          label="Перевести"
          disabled={!to || (need && !reason.trim())}
          onSubmit={() => to && void s.run(() => api.setStatus(t.id, to, reason.trim()))}
        />
      }
    >
      <span className="muted">
        Сейчас: <b>{STATUS_LABEL[t.status]}</b>
      </span>
      <label className="field">
        <span>Новый статус</span>
        <select className="select" value={to} onChange={(e) => setTo(e.target.value as TicketStatus)}>
          {options.map((o) => (
            <option key={o} value={o}>
              {STATUS_LABEL[o]}
            </option>
          ))}
        </select>
        <small>«Подтверждено» ставит только повторная проверка сканером.</small>
      </label>
      <label className="field">
        <span>Причина{need ? "" : " (необязательно)"}</span>
        <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 89 }} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
        {need && <small>Для этого перехода причина обязательна — она попадёт в историю заявки и журнал аудита.</small>}
      </label>
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

function RiskModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const [to, setTo] = useState<TicketStatus>("risk_accepted");
  const [reason, setReason] = useState("");
  const s = useSubmit(onDone);
  return (
    <Modal
      title={`Исключение для заявки №${t.id}`}
      onClose={onClose}
      footer={
        <Footer
          onClose={onClose}
          busy={s.busy}
          danger
          label={to === "risk_accepted" ? "Принять риск" : "Отметить ложным"}
          disabled={!reason.trim()}
          onSubmit={() => void s.run(() => api.setStatus(t.id, to, reason.trim()))}
        />
      }
    >
      <div className="alert alert-warn">
        Заявка закроется без исправления: уязвимости останутся на хостах, повторная проверка по ней проводиться не будет. Вернуть заявку в работу сможет
        руководитель, указав причину.
      </div>
      <div className="seg" role="radiogroup" aria-label="Вид исключения">
        <button type="button" role="radio" aria-checked={to === "risk_accepted"} onClick={() => setTo("risk_accepted")}>
          Принять риск
        </button>
        <button type="button" role="radio" aria-checked={to === "false_positive"} onClick={() => setTo("false_positive")}>
          Ложное срабатывание
        </button>
      </div>
      <label className="field">
        <span>Обоснование</span>
        <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 89 }} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
        <small>Утверждающий и дата пересмотра появятся на этапе 2.</small>
      </label>
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

function OverrideModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const [sev, setSev] = useState<Severity | "">(t.severity_overridden ? t.severity : "");
  const [reason, setReason] = useState("");
  const s = useSubmit(onDone);
  return (
    <Modal
      title={`Уровень заявки №${t.id}`}
      onClose={onClose}
      footer={
        <Footer
          onClose={onClose}
          busy={s.busy}
          label={sev ? "Переопределить" : "Вернуть уровень «Сканера»"}
          disabled={!reason.trim()}
          onSubmit={() => void s.run(() => api.override(t.id, { severity: sev || null, priority: null, reason: reason.trim() }))}
        />
      }
    >
      <span className="muted">
        Уровень «Сканера»: <b>{SEVERITY_LABEL[t.scanner_severity]}</b>
      </span>
      <label className="field">
        <span>Уровень заявки</span>
        <select className="select" value={sev} onChange={(e) => setSev(e.target.value as Severity | "")}>
          <option value="">как в «Сканере»</option>
          {SEVERITIES.map((x) => (
            <option key={x} value={x}>
              {SEVERITY_LABEL[x]}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Причина</span>
        <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 89 }} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
      </label>
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

function VerifyModal({ t, onClose, onDone }: { t: TicketDetail; onClose: () => void; onDone: () => void }) {
  const hosts = t.hosts.filter((h) => h.status !== "confirmed");
  const [picked, setPicked] = useState<string[]>(hosts.map((h) => h.host));
  const canFix = t.can.statuses.includes("fixed");
  const [markFixed, setMarkFixed] = useState(canFix);
  const s = useSubmit(() => {
    notifyJobs();
    onDone();
  });
  const toggle = (h: string) => setPicked((p) => (p.includes(h) ? p.filter((x) => x !== h) : [...p, h]));
  return (
    <Modal
      title="Повторная проверка"
      onClose={onClose}
      footer={
        <Footer
          onClose={onClose}
          busy={s.busy}
          label="Запустить проверку"
          disabled={!picked.length}
          onSubmit={() => void s.run(() => api.verify(t.id, picked.length === hosts.length ? undefined : picked, markFixed && canFix))}
        />
      }
    >
      <span className="muted">
        «Сканер» запустит прицельный прогон по выбранным хостам модулями, которые нашли уязвимости. Хост подтверждается, только если проверен полностью и
        уязвимость не найдена; непроверенные хосты останутся открытыми с причиной.
      </span>
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 8 }}>
        <legend className="faint" style={{ fontSize: 13, marginBottom: 8 }}>
          Хосты ({picked.length} из {hosts.length})
        </legend>
        {hosts.map((h) => (
          <label key={h.host} className="check" style={{ alignItems: "center" }}>
            <input type="checkbox" checked={picked.includes(h.host)} onChange={() => toggle(h.host)} />
            <span className="mono" style={{ flex: 1 }}>
              {h.host}
            </span>
            <HostStatusPill status={h.status} />
          </label>
        ))}
      </fieldset>
      {canFix && (
        <label className="check">
          <input type="checkbox" checked={markFixed} onChange={(e) => setMarkFixed(e.target.checked)} />
          <span>
            <b>Перевести в «Исправлено, ждёт проверки»</b>
            <small>Если проверка найдёт уязвимость, заявка вернётся в работу со статусом «Не подтверждено».</small>
          </span>
        </label>
      )}
      {s.error && <ErrorAlert error={s.error} />}
    </Modal>
  );
}

/**
 * Действия с заявкой по блоку `can` из API: «Взять», «Исправлено — проверить», назначение,
 * перевод статуса, исключения, переопределение уровня, наблюдение. Одна главная кнопка.
 */
export function TicketActions({ t, onChanged, compact }: { t: TicketDetail; onChanged: () => void; compact?: boolean }) {
  const { me, has } = useAuth();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => setDialog(null);
  const done = () => {
    setDialog(null);
    onChanged();
  };
  const quick = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const mine = t.assignee?.id === me?.id;
  const verifying = t.verifications.some((v) => v.status === "requested" || v.status === "running");
  const work = t.can.statuses.filter((s) => !EXCEPTION_STATUSES.includes(s) || EXCEPTION_STATUSES.includes(t.status));
  const canException = t.can.statuses.some((s) => EXCEPTION_STATUSES.includes(s)) && !EXCEPTION_STATUSES.includes(t.status);
  // Главная кнопка: свободную — взять, свою — отправить на проверку.
  const primary = t.can.take ? "take" : t.can.verify && (mine || !t.can.take) ? "verify" : null;
  const sm = compact ? " btn-sm" : "";

  return (
    <>
      <div className="inline ticket-actions">
        {t.can.take && (
          <button type="button" className={`btn${sm} ${primary === "take" ? "btn-primary" : ""}`} disabled={busy} onClick={() => void quick(() => api.take(t.id))}>
            <Hand size={15} aria-hidden="true" /> Взять
          </button>
        )}
        {t.can.verify && (
          <button type="button" className={`btn${sm} ${primary === "verify" ? "btn-primary" : ""}`} onClick={() => setDialog("verify")}>
            <CheckCheck size={15} aria-hidden="true" /> Исправлено — проверить
          </button>
        )}
        {verifying && <span className="pill pill-info pill-running">Идёт проверка</span>}
        {t.can.assign && (
          <button type="button" className={`btn${sm}`} onClick={() => setDialog("assign")}>
            <UserPlus size={15} aria-hidden="true" /> Назначить
          </button>
        )}
        {work.length > 0 && (
          <button type="button" className={`btn${sm}`} onClick={() => setDialog("status")}>
            <ArrowRightLeft size={15} aria-hidden="true" /> Перевести
          </button>
        )}
        {canException && (
          <button type="button" className={`btn${sm} btn-danger`} onClick={() => setDialog("risk")}>
            <ShieldOff size={15} aria-hidden="true" /> Принять риск
          </button>
        )}
        {t.can.override && !compact && (
          <button type="button" className={`btn${sm} btn-ghost`} onClick={() => setDialog("override")}>
            <SlidersHorizontal size={15} aria-hidden="true" /> Уровень
          </button>
        )}
        {has("view") && !compact && (
          <button
            type="button"
            className={`btn${sm} btn-ghost`}
            disabled={busy}
            onClick={() => void quick(() => api.watch(t.id, !t.watching))}
            aria-pressed={t.watching}
          >
            {t.watching ? <BellOff size={15} aria-hidden="true" /> : <Bell size={15} aria-hidden="true" />}
            {t.watching ? "Не наблюдать" : "Наблюдать"}
          </button>
        )}
      </div>
      {error && <ErrorAlert error={error} />}
      {dialog === "assign" && <AssignModal t={t} onClose={close} onDone={done} />}
      {dialog === "status" && <StatusModal t={t} onClose={close} onDone={done} />}
      {dialog === "risk" && <RiskModal t={t} onClose={close} onDone={done} />}
      {dialog === "override" && <OverrideModal t={t} onClose={close} onDone={done} />}
      {dialog === "verify" && <VerifyModal t={t} onClose={close} onDone={done} />}
    </>
  );
}

