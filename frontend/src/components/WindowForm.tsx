import { useState } from "react";
import { Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { WindowIn, WindowKind, WindowOut } from "../api/types";
import { fmtMinutes, isoToZoned, TIMEZONES, WEEKDAYS, durationBetween, endTime, zonedToIso } from "../lib/zoned";
import { ConfirmModal, ErrorAlert, Modal } from "./ui";

const KIND_TABS: { id: WindowKind; label: string }[] = [
  { id: "recurring", label: "Повторяющееся" },
  { id: "once", label: "Разовое" },
  { id: "blackout", label: "Блэкаут" },
];

function splitHosts(s: string): string[] {
  return s
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Создание и правка окна обслуживания или блэкаута. Время — в часовом поясе окна. */
export function WindowFormModal({
  projectId,
  initial,
  kind: initialKind,
  onClose,
  onSaved,
}: {
  projectId: string;
  initial?: WindowOut;
  kind?: WindowKind;
  onClose: () => void;
  onSaved: (w: WindowOut | null) => void;
}) {
  const editing = !!initial;
  const tz0 = initial?.timezone ?? "Europe/Moscow";
  const [kind, setKind] = useState<WindowKind>(initial?.kind ?? initialKind ?? "recurring");
  const [name, setName] = useState(initial?.name ?? "");
  const [tz, setTz] = useState(tz0);
  const [weekdays, setWeekdays] = useState<number[]>(initial?.weekdays ?? [1]);
  const [startTime, setStartTime] = useState(initial?.start_time || "22:00");
  const [finishTime, setFinishTime] = useState(
    initial?.kind === "recurring" ? endTime(initial.start_time, initial.duration_minutes) : "02:00",
  );
  const [validFrom, setValidFrom] = useState(initial?.valid_from ?? "");
  const [validUntil, setValidUntil] = useState(initial?.valid_until ?? "");
  const [startsAt, setStartsAt] = useState(isoToZoned(initial?.starts_at, tz0));
  const [endsAt, setEndsAt] = useState(isoToZoned(initial?.ends_at, tz0));
  const [hosts, setHosts] = useState((initial?.hosts ?? []).join("\n"));
  const [note, setNote] = useState(initial?.note ?? "");
  const [active, setActive] = useState(initial?.is_active ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Длинное повторяющееся окно (больше суток) задаётся через API; здесь — начало и конец в пределах суток.
  const longRecurring = !!initial && initial.kind === "recurring" && initial.duration_minutes > 24 * 60;
  const duration = longRecurring ? initial!.duration_minutes : durationBetween(startTime, finishTime);
  const toggleDay = (d: number) =>
    setWeekdays((cur) => (cur.includes(d) ? cur.filter((x) => x !== d) : [...cur, d].sort()));

  const submit = async () => {
    setBusy(true);
    setError(null);
    const data: WindowIn = {
      name: name.trim(),
      kind,
      timezone: tz,
      starts_at: kind === "recurring" ? null : zonedToIso(startsAt, tz),
      ends_at: kind === "recurring" ? null : zonedToIso(endsAt, tz),
      weekdays: kind === "recurring" ? weekdays : [],
      start_time: kind === "recurring" ? startTime : "",
      duration_minutes: kind === "recurring" ? duration : 0,
      valid_from: kind === "recurring" && validFrom ? validFrom : null,
      valid_until: kind === "recurring" && validUntil ? validUntil : null,
      hosts: splitHosts(hosts),
      note: note.trim(),
      is_active: active,
    };
    try {
      const saved = editing ? await api.updateWindow(initial!.id, data) : await api.createWindow(projectId, data);
      onSaved(saved);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.deleteWindow(initial!.id);
      onSaved(null);
    } catch (e) {
      setError((e as Error).message);
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  };

  const title = editing
    ? `${initial!.kind === "blackout" ? "Блэкаут" : "Окно"} «${initial!.name}»`
    : kind === "blackout"
      ? "Новый блэкаут"
      : "Новое окно обслуживания";

  return (
    <>
      <Modal
        title={title}
        onClose={onClose}
        footer={
          <>
            {editing && (
              <button type="button" className="btn btn-ghost" style={{ marginRight: "auto" }} onClick={() => setConfirmDelete(true)}>
                <Trash2 size={15} aria-hidden="true" /> Удалить
              </button>
            )}
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="button" className="btn btn-primary" onClick={submit} disabled={busy || !name.trim()}>
              {busy ? "Сохранение…" : editing ? "Сохранить" : "Создать"}
            </button>
          </>
        }
      >
        {!editing && (
          <div className="seg" role="radiogroup" aria-label="Вид">
            {KIND_TABS.map((k) => (
              <button key={k.id} type="button" role="radio" aria-checked={kind === k.id} onClick={() => setKind(k.id)}>
                {k.label}
              </button>
            ))}
          </div>
        )}
        <label className="field">
          <span>Название</span>
          <input
            className="input"
            value={name}
            maxLength={200}
            onChange={(e) => setName(e.target.value)}
            placeholder={kind === "blackout" ? "Например, «Закрытие квартала»" : "Например, «Ночное окно, вторник»"}
          />
        </label>
        <label className="field">
          <span>Часовой пояс</span>
          <select className="select" value={tz} onChange={(e) => setTz(e.target.value)}>
            {(TIMEZONES.includes(tz) ? TIMEZONES : [tz, ...TIMEZONES]).map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </select>
          <small>Время окна — по часам заказчика.</small>
        </label>
        {kind === "recurring" ? (
          <>
            <div className="field">
              <span id="wf-days">Дни недели</span>
              <div className="inline" role="group" aria-labelledby="wf-days" style={{ gap: 6 }}>
                {WEEKDAYS.map((d, i) => (
                  <button key={d} type="button" className="chip" aria-pressed={weekdays.includes(i)} onClick={() => toggleDay(i)}>
                    {d}
                  </button>
                ))}
              </div>
            </div>
            {longRecurring ? (
              <p className="muted" style={{ margin: 0 }}>
                Начало {initial!.start_time}, длительность {fmtMinutes(initial!.duration_minutes)} — меняется через API.
              </p>
            ) : (
              <div className="form-grid-2">
                <label className="field">
                  <span>Начало</span>
                  <input className="input" type="time" value={startTime} onChange={(e) => setStartTime(e.target.value)} />
                </label>
                <label className="field">
                  <span>Конец</span>
                  <input className="input" type="time" value={finishTime} onChange={(e) => setFinishTime(e.target.value)} />
                  <small>
                    {duration ? `${fmtMinutes(duration)}${durationBetween(startTime, finishTime) && finishTime <= startTime ? ", до утра следующего дня" : ""}` : ""}
                  </small>
                </label>
              </div>
            )}
            <div className="form-grid-2">
              <label className="field">
                <span>Действует с (необязательно)</span>
                <input className="input" type="date" value={validFrom} onChange={(e) => setValidFrom(e.target.value)} />
              </label>
              <label className="field">
                <span>по (необязательно)</span>
                <input className="input" type="date" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} />
              </label>
            </div>
          </>
        ) : (
          <div className="form-grid-2">
            <label className="field">
              <span>Начало</span>
              <input className="input" type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} />
            </label>
            <label className="field">
              <span>Конец</span>
              <input className="input" type="datetime-local" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} />
            </label>
          </div>
        )}
        <label className="field">
          <span>Хосты (необязательно)</span>
          <textarea
            className="textarea"
            style={{ minHeight: 72 }}
            value={hosts}
            onChange={(e) => setHosts(e.target.value)}
            placeholder={"10.20.1.11\n10.20.1.12"}
          />
          <small>
            {kind === "blackout"
              ? "Пусто — изменения запрещены во всём проекте. Иначе — только на этих хостах."
              : "Пусто — все хосты проекта. По одному на строку или через запятую."}
          </small>
        </label>
        <label className="field">
          <span>Примечание (необязательно)</span>
          <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 55 }} value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} />
        </label>
        {editing && (
          <label className="inline" style={{ gap: 8 }}>
            <input type="checkbox" className="cb" checked={active} onChange={(e) => setActive(e.target.checked)} />
            {kind === "blackout" ? "Блэкаут действует" : "Окно включено — в него можно ставить заявки"}
          </label>
        )}
        {error && <ErrorAlert error={error} />}
      </Modal>
      {confirmDelete && (
        <ConfirmModal title="Удалить окно?" confirmLabel="Удалить" busy={busy} onConfirm={() => void remove()} onClose={() => setConfirmDelete(false)}>
          <p style={{ margin: 0 }}>
            «{initial!.name}» будет удалено. Окно с открытыми заявками удалить нельзя — снимите заявки или отключите окно.
          </p>
        </ConfirmModal>
      )}
    </>
  );
}
