import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { CheckCheck, ClipboardList, Lock, ScrollText, Wrench } from "lucide-react";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ErrorAlert } from "../components/ui";
import { safeNext } from "../lib/format";

export function LoginPage() {
  const { me, login } = useAuth();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (me) return <Navigate to={safeNext(params.get("next"))} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      const ex = err as ApiError;
      setError(
        ex.status === 401
          ? "Неверное имя пользователя или пароль"
          : ex.status === 429
            ? "Слишком много неудачных попыток. Повторите позже."
            : ex.message,
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <section className="login-art">
        <div className="brand" style={{ padding: 0 }}>
          <div className="brand-mark" aria-hidden="true">
            <Wrench size={18} />
          </div>
          <span className="brand-name" style={{ color: "#e6eaf0" }}>
            Устранение
          </span>
        </div>
        <div className="stack" style={{ gap: 18 }}>
          <h1>Каждая найденная уязвимость — до подтверждённого исправления</h1>
          <p>Заявки из плана исправлений «Сканера», исполнители и сроки работ, повторная проверка прицельным прогоном и закрытие с доказательством.</p>
          <ul>
            <li>
              <ClipboardList size={18} aria-hidden="true" /> Заявки сгруппированы как в «Что исправить»
            </li>
            <li>
              <CheckCheck size={18} aria-hidden="true" /> Закрытие — только по повторной проверке сканером
            </li>
            <li>
              <ScrollText size={18} aria-hidden="true" /> Все действия записываются в журнал аудита
            </li>
          </ul>
        </div>
        <span style={{ color: "#7d8794", fontSize: 12 }}>Работа ведётся только с системами заказчика в рамках договора.</span>
      </section>
      <section className="login-form">
        <form onSubmit={submit} aria-label="Вход в систему">
          <div className="stack" style={{ gap: 6 }}>
            <h1>Вход</h1>
            <span className="muted">Используйте учётную запись, выданную администратором.</span>
          </div>
          <label className="field">
            <span>Имя пользователя</span>
            <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
          </label>
          <label className="field">
            <span>Пароль</span>
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          {error && <ErrorAlert error={error} />}
          <button type="submit" className="btn btn-primary" style={{ height: 42 }} disabled={busy || !username || !password}>
            <Lock size={16} aria-hidden="true" />
            {busy ? "Вход…" : "Войти"}
          </button>
        </form>
      </section>
    </div>
  );
}
