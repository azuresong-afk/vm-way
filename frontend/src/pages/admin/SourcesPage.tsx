import { useState } from "react";
import { Link2, Link2Off, Pencil, PlugZap, Plus, Trash2 } from "lucide-react";
import { api } from "../../api/client";
import type { LinkOut, SourceIn, SourceOut, SourceTestOut } from "../../api/types";
import { projectLabel, useProject } from "../../auth/ProjectContext";
import { ConfirmModal, Drawer, Empty, ErrorAlert, Loading, Modal } from "../../components/ui";
import { fmtDate } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

function SourceModal({ source, onClose, onDone }: { source: SourceOut | null; onClose: () => void; onDone: () => void }) {
  const [d, setD] = useState<SourceIn>({
    name: source?.name ?? "«Сканер»",
    base_url: source?.base_url ?? "https://",
    web_url: source?.web_url ?? "",
    username: source?.username ?? "",
    password: "",
    verify_tls: source?.verify_tls ?? true,
    auto_import: source?.auto_import ?? true,
    poll_minutes: source?.poll_minutes ?? 15,
    sync_false_positives: source?.sync_false_positives ?? false,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const up = (patch: Partial<SourceIn>) => setD((x) => ({ ...x, ...patch }));
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const data = { ...d, password: d.password || undefined };
      if (source) await api.updateSource(source.id, data);
      else await api.createSource(data);
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={source ? `Источник «${source.name}»` : "Подключить «Сканер»"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy || !d.name.trim() || !d.base_url.trim()}>
            {busy ? "Сохранение…" : "Сохранить"}
          </button>
        </>
      }
    >
      <div className="alert alert-info">
        Заведите в «Сканере» сервисную учётную запись: для импорта достаточно роли auditor, для повторной проверки нужна роль operator и право
        host_credentials.
      </div>
      <div className="grid-2">
        <label className="field">
          <span>Название</span>
          <input className="input" value={d.name} onChange={(e) => up({ name: e.target.value })} />
        </label>
        <label className="field">
          <span>Адрес API</span>
          <input className="input mono" value={d.base_url} onChange={(e) => up({ base_url: e.target.value })} placeholder="https://scanner.example/api" />
        </label>
        <label className="field">
          <span>Адрес веб-интерфейса</span>
          <input className="input mono" value={d.web_url} onChange={(e) => up({ web_url: e.target.value })} placeholder="https://scanner.example" />
          <small>Для ссылок «Открыть в «Сканере»»</small>
        </label>
        <label className="field">
          <span>Учётная запись</span>
          <input className="input" value={d.username} onChange={(e) => up({ username: e.target.value })} autoComplete="off" />
        </label>
        <label className="field">
          <span>Пароль</span>
          <input
            className="input"
            type="password"
            value={d.password}
            onChange={(e) => up({ password: e.target.value })}
            autoComplete="new-password"
            placeholder={source?.has_password ? "сохранён — оставьте пустым" : ""}
          />
          <small>Хранится зашифрованным, в интерфейс не возвращается</small>
        </label>
        <label className="field">
          <span>Опрос, минут</span>
          <input className="input" type="number" min={1} max={1440} value={d.poll_minutes} onChange={(e) => up({ poll_minutes: Number(e.target.value) || 15 })} />
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={d.auto_import} onChange={(e) => up({ auto_import: e.target.checked })} />
        <span>
          <b>Импортировать новые прогоны автоматически</b>
          <small>Иначе — только по кнопке «Импортировать новые прогоны» на «Сводке».</small>
        </span>
      </label>
      <label className="check">
        <input type="checkbox" checked={!!d.sync_false_positives} onChange={(e) => up({ sync_false_positives: e.target.checked })} />
        <span>
          <b>Отмечать ложные срабатывания в «Сканере»</b>
          <small>Утверждённое исключение «Ложное срабатывание» можно отметить и в «Сканере»; снятие исключения снимает отметку. Нужна роль operator у учётной записи.</small>
        </span>
      </label>
      <label className="check">
        <input type="checkbox" checked={d.verify_tls} onChange={(e) => up({ verify_tls: e.target.checked })} />
        <span>
          <b>Проверять сертификат TLS</b>
          <small>Отключайте только на стенде с самоподписанным сертификатом.</small>
        </span>
      </label>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

/** Шторка источника: проверка связи и привязка проектов «Сканера» к проектам «Устранения». */
function SourceDrawer({ source, onClose }: { source: SourceOut; onClose: () => void }) {
  const { projects, current } = useProject();
  const engs = useAsync(() => api.engagements(source.id), [source.id]);
  const linkedIds = [...new Set((engs.data ?? []).map((e) => e.linked_project_id).filter((x): x is string => !!x))];
  const links = useAsync<LinkOut[]>(
    async () => (await Promise.all(linkedIds.map((pid) => api.links(pid)))).flat(),
    [linkedIds.join(",")],
    linkedIds.length > 0,
  );
  const [test, setTest] = useState<SourceTestOut | null>(null);
  const [target, setTarget] = useState<string>(current?.id ?? projects[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await engs.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const nameOf = (pid: string) => {
    const p = projects.find((x) => x.id === pid);
    return p ? projectLabel(p) : "другой проект";
  };
  return (
    <Drawer title={source.name} onClose={onClose} header={<span className="mono faint">{source.base_url}</span>}>
      <div className="inline">
        <button
          type="button"
          className="btn btn-sm"
          disabled={busy}
          onClick={() => {
            setTest(null);
            void run(async () => setTest(await api.testSource(source.id)));
          }}
        >
          <PlugZap size={15} aria-hidden="true" /> Проверить связь
        </button>
        {source.last_poll_at && <span className="faint" style={{ fontSize: 13 }}>последний опрос {fmtDate(source.last_poll_at)}</span>}
      </div>
      {test &&
        (test.ok ? (
          <div className={`alert ${test.warnings?.length ? "alert-warn" : "alert-ok"}`}>
            <span>
              Вход выполнен: {test.username}, роли {test.roles?.join(", ") || "—"}.
              {test.warnings?.map((w) => (
                <span key={w} style={{ display: "block" }}>
                  {w}
                </span>
              ))}
            </span>
          </div>
        ) : (
          <ErrorAlert error={test.error ?? "Нет связи"} />
        ))}
      {source.last_error && <ErrorAlert error={`Последняя ошибка опроса: ${source.last_error}`} />}
      {error && <ErrorAlert error={error} />}
      <div className="stack" style={{ gap: 8 }}>
        <h3>Проекты «Сканера»</h3>
        {projects.length > 0 && (
          <label className="field">
            <span>Привязывать к проекту «Устранения»</span>
            <select className="select" value={target} onChange={(e) => setTarget(e.target.value)}>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {projectLabel(p)}
                </option>
              ))}
            </select>
          </label>
        )}
        {engs.error && <ErrorAlert error={engs.error} onRetry={() => void engs.reload()} />}
        {engs.loading && !engs.data && <Loading />}
        {engs.data && engs.data.length === 0 && <Empty title="В «Сканере» нет доступных проектов" />}
        {engs.data?.map((e) => {
          const link = links.data?.find((l) => l.source_id === source.id && l.engagement_id === e.id);
          return (
            <div key={e.id} className="list-row">
              <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                <span>
                  №{e.id} · {e.name}
                </span>
                <span className="faint" style={{ fontSize: 12.5 }}>
                  {[e.client, e.contract_ref].filter(Boolean).join(" · ") || "—"}
                  {e.linked_project_id && ` → ${nameOf(e.linked_project_id)}`}
                </span>
              </span>
              {e.linked_project_id ? (
                <button type="button" className="btn btn-sm btn-ghost" disabled={busy || !link} onClick={() => link && void run(() => api.deleteLink(link.id))}>
                  <Link2Off size={14} aria-hidden="true" /> Снять
                </button>
              ) : (
                <button type="button" className="btn btn-sm" disabled={busy || !target} onClick={() => void run(() => api.createLink(target, source.id, e.id))}>
                  <Link2 size={14} aria-hidden="true" /> Привязать
                </button>
              )}
            </div>
          );
        })}
      </div>
    </Drawer>
  );
}

export function SourcesPage() {
  const list = useAsync(() => api.sources(), []);
  const [edit, setEdit] = useState<SourceOut | "new" | null>(null);
  const [open, setOpen] = useState<SourceOut | null>(null);
  const [del, setDel] = useState<SourceOut | null>(null);
  const [delBusy, setDelBusy] = useState(false);
  const [delError, setDelError] = useState<string | null>(null);
  const remove = async () => {
    if (!del) return;
    setDelBusy(true);
    setDelError(null);
    try {
      await api.deleteSource(del.id);
      setDel(null);
      void list.reload();
    } catch (e) {
      setDelError((e as Error).message);
    } finally {
      setDelBusy(false);
    }
  };
  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Источники</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => setEdit("new")}>
            <Plus size={15} aria-hidden="true" /> Подключить «Сканер»
          </button>
        </div>
      </div>
      <section className="card">
        {list.error && <ErrorAlert error={list.error} onRetry={() => void list.reload()} />}
        {list.loading && !list.data && <Loading />}
        {list.data && list.data.length === 0 && (
          <Empty title="«Сканер» не подключён" icon={<PlugZap size={28} />}>
            Подключите «Сканер» сервисной учётной записью и привяжите его проекты к проектам «Устранения».
          </Empty>
        )}
        {list.data && list.data.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Источник</th>
                  <th>Учётная запись</th>
                  <th>Импорт</th>
                  <th>Состояние</th>
                  <th className="right">Действия</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((s) => (
                  <tr key={s.id} className="clickable" onClick={() => setOpen(s)}>
                    <td>
                      <span className="ticket-title">{s.name}</span>
                      <span className="faint ticket-sub mono">{s.base_url}</span>
                    </td>
                    <td className="mono">{s.username || <span className="faint">—</span>}</td>
                    <td>{s.auto_import ? `раз в ${s.poll_minutes} мин` : "по кнопке"}</td>
                    <td>
                      {s.last_error ? (
                        <span className="pill pill-danger" title={s.last_error}>
                          Ошибка опроса
                        </span>
                      ) : s.last_poll_at ? (
                        <span className="pill pill-ok">Работает</span>
                      ) : (
                        <span className="pill pill-muted">Не опрашивался</span>
                      )}
                    </td>
                    <td className="right nowrap" onClick={(e) => e.stopPropagation()}>
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => setEdit(s)}>
                        <Pencil size={14} aria-hidden="true" /> Изменить
                      </button>
                      <button type="button" className="btn btn-sm btn-ghost icon-btn" aria-label={`Удалить источник ${s.name}`} onClick={() => setDel(s)}>
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {edit && (
        <SourceModal
          source={edit === "new" ? null : edit}
          onClose={() => setEdit(null)}
          onDone={() => {
            setEdit(null);
            void list.reload();
          }}
        />
      )}
      {open && <SourceDrawer source={open} onClose={() => setOpen(null)} />}
      {del && (
        <ConfirmModal
          title={`Удалить источник «${del.name}»?`}
          confirmLabel="Удалить источник"
          busy={delBusy}
          error={delError}
          onConfirm={() => void remove()}
          onClose={() => {
            setDel(null);
            setDelError(null);
          }}
        >
          <p style={{ margin: 0 }}>
            Подключение и сохранённый пароль будут удалены без возможности восстановления. Удалить можно только источник без привязок и без
            импортированных прогонов — иначе отключите автоимпорт.
          </p>
        </ConfirmModal>
      )}
    </>
  );
}
