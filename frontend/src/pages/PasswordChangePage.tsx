import { KeyRound, LogOut } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { usePasswordForm } from "../components/usePasswordForm";
import { Brand } from "../components/Layout";

/** Экран вместо приложения, пока пользователь не сменил пароль, выданный администратором. */
export function PasswordChangePage() {
  const { me, logout } = useAuth();
  const form = usePasswordForm();
  return (
    <div className="login-form" style={{ minHeight: "100%" }}>
      <form onSubmit={form.submit} aria-label="Смена пароля">
        <Brand />
        <div className="stack" style={{ gap: 6 }}>
          <h1>Задайте свой пароль</h1>
          <span className="muted">
            Пароль учётной записи {me?.username} выдал администратор. Чтобы продолжить, смените его на свой: его не должен знать никто, кроме вас.
          </span>
        </div>
        {form.fields}
        <button type="submit" className="btn btn-primary" style={{ height: 42 }} disabled={form.busy || !form.ready}>
          <KeyRound size={16} aria-hidden="true" />
          {form.busy ? "Сохранение…" : "Сменить пароль и продолжить"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={logout}>
          <LogOut size={15} aria-hidden="true" /> Выйти
        </button>
      </form>
    </div>
  );
}
