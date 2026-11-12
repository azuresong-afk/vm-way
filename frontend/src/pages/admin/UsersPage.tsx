import { useState } from "react";
import { KeyRound, Pencil, UserPlus } from "lucide-react";
import { api } from "../../api/client";
import type { RolesOut, UserOut } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Empty, ErrorAlert, Loading, Modal } from "../../components/ui";
import { fmtDate } from "../../lib/format";
import { PERM_LABEL, ROLE_LABEL } from "../../lib/labels";
import { useAsync } from "../../lib/useAsync";

interface Draft {
  username: string;
  display_name: string;
  email: string;
  password: string;
  roles: string[];
  extra_perms: string[];
  is_active: boolean;
}

function RolePicker({ roles, value, onChange }: { roles: RolesOut; value: string[]; onChange: (v: string[]) => void }) {
  const toggle = (id: string) => {
    if (id === "admin") return onChange(value.includes("admin") ? [] : ["admin"]);
    const rest = value.filter((r) => r !== "admin");
    onChange(rest.includes(id) ? rest.filter((r) => r !== id) : [...rest, id]);
  };
  return (
    <fieldset className="grid-2" style={{ border: 0, padding: 0, margin: 0 }}>
      <legend className="sr-only">Роли</legend>
      {roles.roles.map((r) => (
        <label key={r.id} className="option-card">
          <input type="checkbox" checked={value.includes(r.id)} onChange={() => toggle(r.id)} />
          <span>
            <b>{r.label}</b>
            <small>{r.perms.map((p) => PERM_LABEL[p] ?? p).join(", ")}</small>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function UserModal({ user, roles, onClose, onDone }: { user: UserOut | null; roles: RolesOut; onClose: () => void; onDone: () => void }) {
  const { me } = useAuth();
  const [d, setD] = useState<Draft>({
    username: user?.username ?? "",
    display_name: user?.display_name ?? "",
    email: user?.email ?? "",
    password: "",
    roles: user?.roles ?? ["engineer"],
    extra_perms: user?.extra_perms ?? [],
    is_active: user?.is_active ?? true,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const self = user?.id === me?.id;
  const up = (patch: Partial<Draft>) => setD((x) => ({ ...x, ...patch }));
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const extra = d.roles.some((r) => r === "engineer" || r === "manager") ? d.extra_perms : [];
      if (user) {
        await api.updateUser(user.id, { display_name: d.display_name, email: d.email, roles: d.roles, extra_perms: extra, is_active: d.is_active });
      } else {
        await api.createUser({ username: d.username.trim(), display_name: d.display_name, email: d.email, password: d.password, roles: d.roles, extra_perms: extra });
      }
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const workRole = d.roles.some((r) => r === "engineer" || r === "manager");
  return (
    <Modal
      title={user ? `Пользователь ${user.username}` : "Новый пользователь"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy || (!user && (!d.username || d.password.length < 10))}>
            {busy ? "Сохранение…" : user ? "Сохранить" : "Создать"}
          </button>
        </>
      }
    >
      <div className="grid-2">
        <label className="field">
          <span>Имя входа</span>
          <input className="input" value={d.username} onChange={(e) => up({ username: e.target.value })} disabled={!!user} autoComplete="off" />
        </label>
        <label className="field">
          <span>Имя для показа</span>
          <input className="input" value={d.display_name} onChange={(e) => up({ display_name: e.target.value })} placeholder="Петрова А. С." />
        </label>
        <label className="field">
          <span>Эл. почта</span>
          <input className="input" type="email" value={d.email} onChange={(e) => up({ email: e.target.value })} />
        </label>
        {!user && (
          <label className="field">
            <span>Пароль</span>
            <input className="input" type="password" value={d.password} onChange={(e) => up({ password: e.target.value })} autoComplete="new-password" />
            <small>Не короче 10 символов. При первом входе пользователь сменит его на свой.</small>
          </label>
        )}
      </div>
      <div className="field">
        <span>Роли</span>
        <RolePicker roles={roles} value={d.roles} onChange={(v) => up({ roles: v })} />
        <small>Администратор не совмещает рабочие роли и не выполняет работ по заявкам.</small>
      </div>
      {workRole && roles.extra_perms.length > 0 && (
        <div className="field">
          <span>Дополнительные права (этап 2)</span>
          {roles.extra_perms.map((x) => (
            <label key={x.id} className="check">
              <input
                type="checkbox"
                checked={d.extra_perms.includes(x.id)}
                onChange={() => up({ extra_perms: d.extra_perms.includes(x.id) ? d.extra_perms.filter((p) => p !== x.id) : [...d.extra_perms, x.id] })}
              />
              <span>{x.label}</span>
            </label>
          ))}
        </div>
      )}
      {user && (
        <label className="check">
          <input type="checkbox" checked={d.is_active} disabled={self} onChange={(e) => up({ is_active: e.target.checked })} />
          <span>
            <b>Учётная запись активна</b>
            <small>{self ? "Отключить самого себя нельзя." : "Отключение сразу завершает все сессии пользователя."}</small>
          </span>
        </label>
      )}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

function PasswordModal({ user, onClose }: { user: UserOut; onClose: () => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.setPassword(user.id, pw);
      setDone(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Новый пароль для ${user.username}`}
      onClose={onClose}
      footer={
        done ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Готово
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="button" className="btn btn-danger" onClick={save} disabled={busy || pw.length < 10}>
              Сменить пароль
            </button>
          </>
        )
      }
    >
      {done ? (
        <div className="alert alert-ok">Пароль изменён. Все прежние сессии пользователя завершены.</div>
      ) : (
        <>
          <div className="alert alert-warn">Все текущие сессии пользователя будут завершены. После входа с этим паролем он должен будет сменить его на свой.</div>
          <label className="field">
            <span>Пароль</span>
            <input className="input" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
            <small>Не короче 10 символов</small>
          </label>
        </>
      )}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

export function UsersPage() {
  const users = useAsync(() => api.users(), []);
  const roles = useAsync(() => api.roles(), []);
  const [edit, setEdit] = useState<UserOut | "new" | null>(null);
  const [pw, setPw] = useState<UserOut | null>(null);
  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Пользователи и роли</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => setEdit("new")} disabled={!roles.data}>
            <UserPlus size={15} aria-hidden="true" /> Добавить пользователя
          </button>
        </div>
      </div>
      <section className="card">
        {users.error && <ErrorAlert error={users.error} onRetry={() => void users.reload()} />}
        {users.loading && !users.data && <Loading />}
        {users.data && users.data.items.length === 0 && <Empty title="Пользователей нет" />}
        {users.data && users.data.items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Пользователь</th>
                  <th>Роли</th>
                  <th>Состояние</th>
                  <th className="hide-md">Создан</th>
                  <th className="right">Действия</th>
                </tr>
              </thead>
              <tbody>
                {users.data.items.map((u) => (
                  <tr key={u.id} className={u.is_active ? undefined : "is-fp"}>
                    <td>
                      <span className="ticket-title">{u.display_name || u.username}</span>
                      <span className="faint ticket-sub mono">{u.username}{u.email ? ` · ${u.email}` : ""}</span>
                    </td>
                    <td>
                      <span className="inline" style={{ gap: 6 }}>
                        {u.roles.length ? u.roles.map((r) => <span key={r} className="tag tag-muted">{ROLE_LABEL[r] ?? r}</span>) : <span className="faint">нет ролей</span>}
                      </span>
                    </td>
                    <td>
                      <span className="inline" style={{ gap: 6 }}>
                        {u.is_active ? <span className="pill pill-ok">Активен</span> : <span className="pill pill-muted">Отключён</span>}
                        {u.is_active && u.must_change_password && (
                          <span className="tag tag-muted" title="Пароль выдан администратором, пользователь ещё не сменил его на свой">
                            ждёт смены пароля
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="hide-md nowrap faint">{fmtDate(u.created_at)}</td>
                    <td className="right nowrap">
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => setEdit(u)} disabled={!roles.data}>
                        <Pencil size={14} aria-hidden="true" /> Изменить
                      </button>
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => setPw(u)}>
                        <KeyRound size={14} aria-hidden="true" /> Пароль
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {edit && roles.data && (
        <UserModal
          user={edit === "new" ? null : edit}
          roles={roles.data}
          onClose={() => setEdit(null)}
          onDone={() => {
            setEdit(null);
            void users.reload();
          }}
        />
      )}
      {pw && <PasswordModal user={pw} onClose={() => setPw(null)} />}
    </>
  );
}
