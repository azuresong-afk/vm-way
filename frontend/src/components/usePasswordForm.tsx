import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { ErrorAlert } from "./ui";

const MIN_LENGTH = 10;

/** Поля и проверка смены своего пароля — общие для окна в меню и экрана обязательной смены. */
export function usePasswordForm(onDone?: () => void) {
  const { changePassword } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const problem =
    next && next === current ? "Новый пароль должен отличаться от текущего" : repeat && repeat !== next ? "Пароли не совпадают" : null;
  const ready = !!current && next.length >= MIN_LENGTH && repeat === next && next !== current;

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      onDone?.();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const fields = (
    <>
      <label className="field">
        <span>Текущий пароль</span>
        <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
      </label>
      <div className="field">
        <label className="field">
          <span>Новый пароль</span>
          <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
        </label>
        <small>Не короче {MIN_LENGTH} символов</small>
      </div>
      <label className="field">
        <span>Новый пароль ещё раз</span>
        <input className="input" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} required />
      </label>
      {problem && <div className="alert alert-warn">{problem}</div>}
      {error && <ErrorAlert error={error} />}
    </>
  );
  return { fields, submit, busy, ready };
}
