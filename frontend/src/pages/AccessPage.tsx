import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { KeyRound, Pencil, Plug, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { HostKeyOut, SshAuth, SshBecome, SshCheckOut, SshCheckResult, SshCredentialIn, SshCredentialOut, SshHostOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { ChipPicker } from "../components/ChipPicker";
import { ConfirmModal, Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtAgo, fmtDate, fmtNumber, plural } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const RESULT_PILL: Record<SshCheckResult, string> = {
  ok: "pill-ok",
  unreachable: "pill-muted",
  timeout: "pill-muted",
  auth_failed: "pill-danger",
  host_key_mismatch: "pill-danger",
  become_failed: "pill-warn",
  error: "pill-warn",
};

const WHY_LABEL: Record<NonNullable<SshHostOut["credential"]>["why"], string> = {
  host: "адрес в охвате",
  group: "группа",
  subnet: "подсеть",
  all: "все хосты проекта",
};

const BECOME_TEXT = (c: SshCredentialOut) =>
  c.become === "none" ? "без повышения" : c.has_become_password ? "sudo, свой пароль" : c.auth === "key" ? "sudo (NOPASSWD)" : "sudo";

/** Отпечаток покороче: SHA256:abcd…wxyz, полный — в подсказке. */
function Fingerprint({ value }: { value: string }) {
  const short = value.length > 30 ? `${value.slice(0, 18)}…${value.slice(-6)}` : value;
  return (
    <span className="mono" title={value} style={{ fontSize: 12 }}>
      {short}
    </span>
  );
}

function Scope({ c }: { c: SshCredentialOut }) {
  if (!c.hosts.length && !c.groups.length) return <span className="faint">все хосты проекта</span>;
  return (
    <span className="rule-cond" style={{ marginTop: 0 }}>
      {c.groups.map((g) => (
        <span key={`g-${g}`} className="tag" title="Группа активов «Сканера»">
          {g}
        </span>
      ))}
      {c.hosts.slice(0, 6).map((h) => (
        <span key={h} className="tag tag-muted mono">
          {h}
        </span>
      ))}
      {c.hosts.length > 6 && <span className="faint">ещё {c.hosts.length - 6}</span>}
    </span>
  );
}

function KeyPill({ k }: { k: HostKeyOut | undefined }) {
  if (!k) return <span className="pill pill-muted">не закреплён</span>;
  if (k.status === "mismatch") return <span className="pill pill-danger">ключ изменился</span>;
  return <span className="pill pill-ok">закреплён</span>;
}

/** Создание и правка учётки. Секреты только вводятся: сервер их не возвращает. */
function CredentialForm({
  projectId,
  initial,
  onClose,
  onSaved,
}: {
  projectId: string;
  initial?: SshCredentialOut;
  onClose: () => void;
  onSaved: () => void;
}) {
  const facets = useAsync(() => api.assetFacets(projectId), [projectId]);
  const [name, setName] = useState(initial?.name ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [port, setPort] = useState(String(initial?.port ?? 22));
  const [auth, setAuth] = useState<SshAuth>(initial?.auth ?? "password");
  const [password, setPassword] = useState("");
  const [key, setKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [become, setBecome] = useState<SshBecome>(initial?.become ?? "sudo");
  const [becomePassword, setBecomePassword] = useState("");
  const [clearBecome, setClearBecome] = useState(false);
  const [scope, setScope] = useState((initial?.hosts ?? []).join("\n"));
  const [groups, setGroups] = useState(initial?.groups ?? []);
  const [note, setNote] = useState(initial?.note ?? "");
  const [active, setActive] = useState(initial?.is_active ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const authChanged = !!initial && initial.auth !== auth;
  const needSecret = !initial || authChanged;
  const secretGiven = auth === "password" ? !!password : !!key.trim();
  const portNum = Number(port);
  const canSubmit =
    !busy && !!name.trim() && !!username.trim() && Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535 && (!needSecret || secretGiven);

  const readKey = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f && f.size <= 16 * 1024) setKey(await f.text());
    e.target.value = "";
  };

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    const data: SshCredentialIn = {
      name: name.trim(),
      username: username.trim(),
      auth,
      port: portNum,
      become,
      hosts: scope
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      groups,
      is_active: active,
      note: note.trim(),
    };
    if (auth === "password" && password) data.password = password;
    if (auth === "key" && key.trim()) {
      data.private_key = key;
      data.passphrase = passphrase;
    }
    if (become === "sudo" && becomePassword) data.become_password = becomePassword;
    if (initial && clearBecome && !becomePassword) data.clear_become_password = true;
    try {
      if (initial) await api.updateSshCredential(initial.id, data);
      else await api.createSshCredential(projectId, data);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await api.deleteSshCredential(initial!.id);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  };

  const keepHint = initial && !authChanged ? "Пусто — оставить сохранённый." : undefined;

  return (
    <>
      <Modal
        title={initial ? `Учётка «${initial.name}»` : "Новая SSH-учётка"}
        onClose={onClose}
        wide
        footer={
          <>
            {initial && (
              <button type="button" className="btn btn-ghost" style={{ marginRight: "auto" }} onClick={() => setConfirmDelete(true)}>
                <Trash2 size={15} aria-hidden="true" /> Удалить
              </button>
            )}
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="submit" form="ssh-credential-form" className="btn btn-primary" disabled={!canSubmit}>
              {busy ? "Сохранение…" : initial ? "Сохранить" : "Создать"}
            </button>
          </>
        }
      >
        <form id="ssh-credential-form" className="stack" style={{ gap: 16 }} onSubmit={(e) => void submit(e)} autoComplete="off">
          <label className="field">
            <span>Название</span>
            <input className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="Например, «Linux-серверы DMZ»" />
          </label>
          <div className="inline" style={{ alignItems: "flex-end" }}>
            <label className="field" style={{ flex: "3 1 200px" }}>
              <span>Логин на хосте</span>
              <input className="input mono" value={username} maxLength={128} onChange={(e) => setUsername(e.target.value)} placeholder="deploy" />
            </label>
            <label className="field" style={{ flex: "1 1 90px" }}>
              <span>Порт SSH</span>
              <input className="input mono" value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" />
            </label>
          </div>
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Аутентификация</span>
            <div className="grid-2">
              <label className="option-card">
                <input type="radio" name="auth" checked={auth === "password"} onChange={() => setAuth("password")} />
                <span>
                  <b style={{ fontWeight: 500 }}>Пароль</b>
                </span>
              </label>
              <label className="option-card">
                <input type="radio" name="auth" checked={auth === "key"} onChange={() => setAuth("key")} />
                <span>
                  <b style={{ fontWeight: 500 }}>Ключ SSH</b>
                  <small>Ed25519, ECDSA или RSA</small>
                </span>
              </label>
            </div>
          </fieldset>
          {auth === "password" ? (
            <label className="field">
              <span>Пароль</span>
              <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
              {keepHint && <small>{keepHint}</small>}
            </label>
          ) : (
            <>
              <label className="field">
                <span>Закрытый ключ (OpenSSH или PEM)</span>
                <textarea
                  className="textarea mono"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder={initial?.key_fingerprint ? `Сохранён ключ ${initial.key_fingerprint}` : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                  spellCheck={false}
                  style={{ fontSize: 12 }}
                />
                <small>
                  <label className="btn btn-sm btn-ghost" style={{ height: "auto", padding: 0, color: "var(--accent-text)", cursor: "pointer" }}>
                    Загрузить из файла
                    <input type="file" hidden onChange={(e) => void readKey(e)} />
                  </label>
                  {keepHint && ` · ${keepHint}`}
                </small>
              </label>
              {key.trim() && (
                <label className="field">
                  <span>Парольная фраза ключа (если есть)</span>
                  <input className="input" type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="new-password" />
                </label>
              )}
            </>
          )}
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Повышение прав (для раскатки обновлений)</span>
            <div className="grid-2">
              <label className="option-card">
                <input type="radio" name="become" checked={become === "sudo"} onChange={() => setBecome("sudo")} />
                <span>
                  <b style={{ fontWeight: 500 }}>sudo</b>
                  <small>
                    {auth === "password"
                      ? "Пароль подаётся sudo скрыто, через stdin. Можно задать отдельный пароль sudo"
                      : "Нужен NOPASSWD в sudoers или отдельный пароль sudo"}
                  </small>
                </span>
              </label>
              <label className="option-card">
                <input type="radio" name="become" checked={become === "none"} onChange={() => setBecome("none")} />
                <span>
                  <b style={{ fontWeight: 500 }}>Нет</b>
                  <small>Вход сразу под root</small>
                </span>
              </label>
            </div>
          </fieldset>
          {become === "sudo" && (
            <label className="field">
              <span>Отдельный пароль sudo (необязательно)</span>
              <input
                className="input"
                type="password"
                value={becomePassword}
                onChange={(e) => setBecomePassword(e.target.value)}
                autoComplete="new-password"
                disabled={clearBecome}
              />
              {initial?.has_become_password && (
                <label className="inline" style={{ gap: 8, fontSize: 13 }}>
                  <input type="checkbox" className="cb" checked={clearBecome} onChange={(e) => setClearBecome(e.target.checked)} />
                  Удалить сохранённый пароль sudo
                </label>
              )}
            </label>
          )}
          <label className="field">
            <span>Адреса и подсети (необязательно)</span>
            <textarea className="textarea mono" value={scope} onChange={(e) => setScope(e.target.value)} placeholder={"10.20.1.0/24\n10.20.3.31"} spellCheck={false} />
          </label>
          <ChipPicker
            label="Группы активов (необязательно)"
            options={(facets.data?.groups ?? []).map((g) => ({ id: g.name, count: g.assets }))}
            value={groups}
            onChange={setGroups}
            empty={facets.loading ? "Загрузка…" : "Групп нет — они приходят из «Сканера»"}
          />
          <small className="muted" style={{ marginTop: -8 }}>
            Ни адресов, ни групп — учётка подходит всем хостам проекта. Для хоста берётся самая точная учётка: адрес, затем группа, затем
            подсеть (чем уже, тем точнее), затем учётка без охвата.
          </small>
          <label className="field">
            <span>Примечание</span>
            <input className="input" value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="Кто выдал, до какого числа действует" />
          </label>
          {initial && (
            <label className="inline" style={{ gap: 8 }}>
              <input type="checkbox" className="cb" checked={active} onChange={(e) => setActive(e.target.checked)} />
              Учётка включена
            </label>
          )}
          <small className="muted">
            Пароль, ключ и фраза шифруются (AES-GCM) и больше не показываются — ни здесь, ни в журнале аудита. Ключ хоста закрепляется при
            первом входе; если он изменится, подключение будет отклонено до входа.
          </small>
          {error && <ErrorAlert error={error} />}
        </form>
      </Modal>
      {confirmDelete && (
        <ConfirmModal title="Удалить учётку?" confirmLabel="Удалить" busy={busy} onConfirm={() => void remove()} onClose={() => setConfirmDelete(false)}>
          <p style={{ margin: 0 }}>Учётка «{initial!.name}» и её секреты будут удалены. Закреплённые ключи хостов останутся.</p>
        </ConfirmModal>
      )}
    </>
  );
}

/** Проверка входа: id, ОС, sudo; первое подключение закрепляет ключ хоста. */
function CheckModal({
  credential,
  hosts,
  onClose,
  onDone,
}: {
  credential: SshCredentialOut;
  hosts: SshHostOut[];
  onClose: () => void;
  onDone: () => void;
}) {
  const own = hosts.filter((h) => h.in_project && h.credential?.id === credential.id).map((h) => h.host);
  const others = hosts.filter((h) => h.in_project && h.credential?.id !== credential.id).map((h) => h.host);
  const [host, setHost] = useState(credential.last_check?.host || own[0] || "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SshCheckOut | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.checkSshCredential(credential.id, host.trim()));
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const f = result?.facts ?? {};
  return (
    <Modal
      title={`Проверить «${credential.name}»`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Закрыть
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void run()} disabled={busy || !host.trim()}>
            <Plug size={15} aria-hidden="true" /> {busy ? "Подключение…" : "Проверить"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Хост проекта</span>
        <input className="input mono" list="ssh-check-hosts" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.20.1.11" />
        <datalist id="ssh-check-hosts">
          {[...own, ...others].map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
        <small>
          Вход под {credential.username} на порт {credential.port}: <span className="mono">id</span>, ОС из{" "}
          <span className="mono">/etc/os-release</span>
          {credential.become === "sudo" ? ", проверка sudo" : ""}. На хосте ничего не меняется.
        </small>
      </label>
      {error && <ErrorAlert error={error} />}
      {result && (
        <div className={`alert ${result.ok ? "alert-ok" : result.result === "become_failed" ? "alert-warn" : "alert-danger"}`} role="status">
          <div>
            <b style={{ fontWeight: 600 }}>{result.label}.</b> {result.ok ? "" : result.message}
            {f.user && (
              <div style={{ marginTop: 4 }}>
                {f.user} (uid {f.uid}){f.os ? ` · ${f.os}` : ""}
                {f.become === "sudo" && " · sudo работает"}
                {f.become === "root" && " · вход под root"}
              </div>
            )}
            {result.host_key && (
              <div style={{ marginTop: 4 }}>
                {result.key_state === "new" ? "Ключ хоста закреплён: " : result.key_state === "mismatch" ? "Закреплён ключ " : "Ключ хоста совпал: "}
                <span className="mono">{result.host_key.fingerprint}</span>
                {result.host_key.mismatch && (
                  <>
                    , предъявлен <span className="mono">{result.host_key.mismatch.fingerprint}</span>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}

/** Решение по ключу хоста: принять новый (после несовпадения) или сбросить закрепление. */
function KeyDecision({
  hostKey,
  mode,
  onClose,
  onDone,
}: {
  hostKey: HostKeyOut;
  mode: "accept" | "reset";
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      if (mode === "accept") await api.acceptHostKey(hostKey.id, reason.trim());
      else await api.resetHostKey(hostKey.id, reason.trim());
      onDone();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={mode === "accept" ? `Принять новый ключ ${hostKey.host}` : `Сбросить ключ ${hostKey.host}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-danger" onClick={() => void go()} disabled={busy || reason.trim().length < 3}>
            {mode === "accept" ? "Принять ключ" : "Сбросить"}
          </button>
        </>
      }
    >
      <div className="alert alert-warn" role="note">
        <ShieldAlert size={16} aria-hidden="true" />
        <span>
          {mode === "accept"
            ? "Принимайте ключ, только если смена объяснима: хост переустановлен или ключи перевыпущены. Сверьте отпечаток с администратором заказчика по другому каналу."
            : "Следующее подключение закрепит тот ключ, который предъявит хост, без сверки. Если подмена уже идёт, она будет закреплена."}
        </span>
      </div>
      <dl className="kv" style={{ margin: 0 }}>
        <dt>Закреплён</dt>
        <dd>
          <span className="mono" style={{ fontSize: 12.5 }}>
            {hostKey.fingerprint}
          </span>{" "}
          <span className="faint">({hostKey.key_type})</span>
        </dd>
        {hostKey.mismatch && (
          <>
            <dt>Предъявлен</dt>
            <dd>
              <span className="mono" style={{ fontSize: 12.5 }}>
                {hostKey.mismatch.fingerprint || "—"}
              </span>{" "}
              <span className="faint">
                ({hostKey.mismatch.key_type || "тип не согласован"}, {fmtDate(hostKey.mismatch.at)})
              </span>
            </dd>
          </>
        )}
      </dl>
      <label className="field">
        <span>Причина (в журнал аудита)</span>
        <input className="input" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} placeholder="Хост переустановлен, письмо заказчика от …" />
      </label>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

type HostFilter = "all" | "nocred" | "mismatch" | "unpinned";
const HOST_FILTERS: { id: HostFilter; label: string }[] = [
  { id: "all", label: "Все" },
  { id: "mismatch", label: "Ключ изменился" },
  { id: "unpinned", label: "Ключ не закреплён" },
  { id: "nocred", label: "Без учётки" },
];

/** Ключ хоста для порта учётки, которой пойдём на хост (или первый закреплённый). */
function keyFor(h: SshHostOut): HostKeyOut | undefined {
  const port = h.credential?.port ?? 22;
  return h.keys.find((k) => k.port === port) ?? (h.credential ? undefined : h.keys[0]);
}

/** «Доступ к хостам»: SSH-учётки проекта и закреплённые ключи хостов. */
export function AccessPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const canEdit = has("credentials_manage");
  const creds = useAsync(() => api.sshCredentials(projectId), [projectId]);
  const hosts = useAsync(() => api.sshHosts(projectId), [projectId]);
  const [form, setForm] = useState<{ credential?: SshCredentialOut } | null>(null);
  const [checking, setChecking] = useState<SshCredentialOut | null>(null);
  const [decision, setDecision] = useState<{ key: HostKeyOut; mode: "accept" | "reset" } | null>(null);
  const [filter, setFilter] = useState<HostFilter>("all");
  const reload = () => {
    void creds.reload();
    void hosts.reload();
  };

  const hostList = useMemo(() => hosts.data ?? [], [hosts.data]);
  const counts = useMemo(() => {
    const c = { all: hostList.length, nocred: 0, mismatch: 0, unpinned: 0 };
    for (const h of hostList) {
      const k = keyFor(h);
      if (!h.credential && h.in_project) c.nocred++;
      if (h.keys.some((x) => x.status === "mismatch")) c.mismatch++;
      if (!k && h.in_project) c.unpinned++;
    }
    return c;
  }, [hostList]);
  const shown = hostList.filter((h) => {
    if (filter === "nocred") return !h.credential && h.in_project;
    if (filter === "mismatch") return h.keys.some((x) => x.status === "mismatch");
    if (filter === "unpinned") return !keyFor(h) && h.in_project;
    return true;
  });
  const list = creds.data ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Доступ к хостам</h1>
        </div>
        <div className="actions">
          {canEdit && (
            <button type="button" className="btn btn-primary" onClick={() => setForm({})}>
              <Plus size={15} aria-hidden="true" /> Новая учётка
            </button>
          )}
        </div>
      </div>

      {counts.mismatch > 0 && (
        <div className="alert alert-danger" role="alert">
          <ShieldAlert size={16} aria-hidden="true" />
          <span>
            У {fmtNumber(counts.mismatch)} {plural(counts.mismatch, ["хоста", "хостов", "хостов"])} изменился ключ SSH. Подключения к{" "}
            {plural(counts.mismatch, ["нему", "ним", "ним"])} запрещены, пока руководитель не примет новый ключ или не сбросит закрепление.{" "}
            <button type="button" className="link-btn" onClick={() => setFilter("mismatch")}>
              Показать
            </button>
          </span>
        </div>
      )}

      <section className="card" aria-labelledby="creds-head">
        <div className="card-head">
          <h2 id="creds-head">SSH-учётки</h2>
          <span className="faint" style={{ fontSize: 13 }}>
            ими «Устранение» входит на хосты для раскатки обновлений
          </span>
        </div>
        {creds.error && <ErrorAlert error={creds.error} onRetry={() => void creds.reload()} />}
        {creds.loading && !creds.data && <Loading />}
        {creds.data && list.length === 0 && (
          <Empty title="Учёток пока нет" icon={<KeyRound size={28} />}>
            Заведите учётку, выданную заказчиком: логин и пароль или ключ SSH, sudo и хосты, к которым она подходит.
          </Empty>
        )}
        {list.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Учётка</th>
                  <th>Вход</th>
                  <th>Охват</th>
                  <th>Последняя проверка</th>
                  {canEdit && <th className="right">Действия</th>}
                </tr>
              </thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.id} className={c.is_active ? "" : "rule-off"}>
                    <td style={{ minWidth: 200 }}>
                      <span style={{ fontWeight: 500 }}>{c.name}</span>
                      {!c.is_active && <span className="faint"> · выключена</span>}
                      {c.note && (
                        <div className="faint" style={{ fontSize: 12.5 }}>
                          {c.note}
                        </div>
                      )}
                    </td>
                    <td style={{ minWidth: 180 }}>
                      <span className="mono">
                        {c.username}:{c.port}
                      </span>
                      <div className="faint" style={{ fontSize: 12.5 }}>
                        {c.auth === "key" ? `ключ ${c.key_type.replace("ssh-", "")}` : "пароль"} · {BECOME_TEXT(c)}
                      </div>
                      {c.key_fingerprint && <Fingerprint value={c.key_fingerprint} />}
                    </td>
                    <td style={{ minWidth: 160 }}>
                      <Scope c={c} />
                    </td>
                    <td style={{ minWidth: 170 }}>
                      {c.last_check ? (
                        <>
                          <span className={`pill ${RESULT_PILL[c.last_check.result] ?? "pill-muted"}`} title={c.last_check.message}>
                            {c.last_check.label}
                          </span>
                          <div className="faint" style={{ fontSize: 12.5 }}>
                            <span className="mono">{c.last_check.host}</span> · {fmtAgo(c.last_check.at)}
                          </div>
                        </>
                      ) : (
                        <span className="faint">не проверялась</span>
                      )}
                    </td>
                    {canEdit && (
                      <td className="right nowrap">
                        <span className="inline" style={{ gap: 4, justifyContent: "flex-end" }}>
                          <button type="button" className="btn btn-sm" onClick={() => setChecking(c)}>
                            <Plug size={14} aria-hidden="true" /> Проверить
                          </button>
                          <button type="button" className="btn btn-sm" onClick={() => setForm({ credential: c })}>
                            <Pencil size={14} aria-hidden="true" /> Изменить
                          </button>
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="hosts-head">
        <div className="card-head">
          <h2 id="hosts-head">Хосты и ключи</h2>
        </div>
        <div className="picker" role="group" aria-label="Показать хосты" style={{ padding: "0 20px 12px" }}>
          {HOST_FILTERS.map((f) => (
            <button key={f.id} type="button" className="chip" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
              {f.label}
              <span className="picker-count">{fmtNumber(counts[f.id])}</span>
            </button>
          ))}
        </div>
        {hosts.error && <ErrorAlert error={hosts.error} onRetry={() => void hosts.reload()} />}
        {hosts.loading && !hosts.data && <Loading />}
        {hosts.data && shown.length === 0 && <Empty title={hostList.length ? "Таких хостов нет" : "Хостов пока нет — они приходят с прогонами «Сканера»"} />}
        {shown.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Хост</th>
                  <th>Учётка</th>
                  <th>Ключ хоста</th>
                  <th>Закреплён</th>
                  {canEdit && <th className="right">Действия</th>}
                </tr>
              </thead>
              <tbody>
                {shown.map((h) => {
                  const k = keyFor(h);
                  return (
                    <tr key={h.host}>
                      <td className="nowrap">
                        <span className="mono">{h.host}</span>
                        <div className="faint" style={{ fontSize: 12.5 }}>
                          {h.hostname || (h.in_project ? "—" : "нет в проекте")}
                          {h.groups.length > 0 && ` · ${h.groups.join(", ")}`}
                        </div>
                      </td>
                      <td style={{ minWidth: 170 }}>
                        {h.credential ? (
                          <>
                            {h.credential.name}
                            <div className="faint" style={{ fontSize: 12.5 }}>
                              {WHY_LABEL[h.credential.why]}
                              {h.credential.detail && h.credential.why !== "host" ? ` «${h.credential.detail}»` : ""}
                            </div>
                          </>
                        ) : (
                          <span className="faint">нет подходящей</span>
                        )}
                      </td>
                      <td style={{ minWidth: 200 }}>
                        <KeyPill k={k} />
                        {k && (
                          <div>
                            <Fingerprint value={k.fingerprint} />
                            {k.port !== 22 && <span className="faint"> · порт {k.port}</span>}
                          </div>
                        )}
                        {k?.mismatch && (
                          <div className="faint" style={{ fontSize: 12.5 }}>
                            предъявлен <Fingerprint value={k.mismatch.fingerprint || "—"} />
                          </div>
                        )}
                      </td>
                      <td className="nowrap">
                        {k ? (
                          <>
                            {fmtDate(k.pinned_at)}
                            <div className="faint" style={{ fontSize: 12.5 }}>
                              {k.pinned_via === "tofu" ? "при первом входе" : `принят${k.pinned_by ? `: ${k.pinned_by}` : ""}`}
                              {k.last_seen_at && ` · виден ${fmtAgo(k.last_seen_at)}`}
                            </div>
                          </>
                        ) : (
                          <span className="faint">—</span>
                        )}
                      </td>
                      {canEdit && (
                        <td className="right nowrap">
                          {k && (
                            <span className="inline" style={{ gap: 4, justifyContent: "flex-end" }}>
                              {k.status === "mismatch" && k.mismatch?.fingerprint && (
                                <button type="button" className="btn btn-sm" onClick={() => setDecision({ key: k, mode: "accept" })}>
                                  Принять новый
                                </button>
                              )}
                              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setDecision({ key: k, mode: "reset" })}>
                                Сбросить
                              </button>
                            </span>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {form && (
        <CredentialForm
          projectId={projectId}
          initial={form.credential}
          onClose={() => setForm(null)}
          onSaved={() => {
            setForm(null);
            reload();
          }}
        />
      )}
      {checking && <CheckModal credential={checking} hosts={hostList} onClose={() => setChecking(null)} onDone={reload} />}
      {decision && (
        <KeyDecision
          hostKey={decision.key}
          mode={decision.mode}
          onClose={() => setDecision(null)}
          onDone={() => {
            setDecision(null);
            reload();
          }}
        />
      )}
    </>
  );
}
