import { useEffect, useState } from "react";
import { Download, ListChecks, Search } from "lucide-react";
import { api } from "../../api/client";
import type { AuditFilters, AuditOut } from "../../api/types";
import { useProject } from "../../auth/ProjectContext";
import { Pager } from "../../components/Pager";
import { Drawer, Empty, ErrorAlert, Loading } from "../../components/ui";
import { fmtDateFull } from "../../lib/format";
import { AUDIT_ACTION_LABEL } from "../../lib/labels";
import { useAsync } from "../../lib/useAsync";

const GROUPS = [
  { id: "", label: "Все события" },
  { id: "ticket.", label: "Заявки" },
  { id: "run.", label: "Импорт прогонов" },
  { id: "auth.", label: "Вход и выход" },
  { id: "user.", label: "Пользователи" },
  { id: "project.", label: "Проекты" },
  { id: "source.", label: "Источники" },
  { id: "link.", label: "Привязки" },
  { id: "audit.", label: "Журнал" },
];

const RESULT_PILL: Record<string, string> = { ok: "pill-ok", denied: "pill-danger", error: "pill-danger", failed: "pill-danger", partial: "pill-warn" };
const RESULT_LABEL: Record<string, string> = { ok: "Успешно", denied: "Отказано", error: "Ошибка", failed: "Не выполнено", partial: "Частично" };

function Entry({ e, onClose }: { e: AuditOut; onClose: () => void }) {
  return (
    <Drawer title={AUDIT_ACTION_LABEL[e.action] ?? e.action} onClose={onClose} header={<span className="mono faint">№{e.id} · {e.action}</span>}>
      <dl className="kv">
        <dt>Время</dt>
        <dd>{fmtDateFull(e.at)}</dd>
        <dt>Кто</dt>
        <dd>{e.username ?? "система"}</dd>
        <dt>Объект</dt>
        <dd>{e.object_type ? `${e.object_type} ${e.object_id ?? ""}` : "—"}</dd>
        <dt>Результат</dt>
        <dd>
          <span className={`pill ${RESULT_PILL[e.result] ?? "pill-muted"}`}>{RESULT_LABEL[e.result] ?? e.result}</span>
        </dd>
        <dt>IP</dt>
        <dd className="mono">{e.ip || "—"}</dd>
      </dl>
      {e.details && (
        <div className="stack" style={{ gap: 8 }}>
          <h3>Подробности</h3>
          {/* данные выводятся текстом, без разметки */}
          <pre className="evidence">{JSON.stringify(e.details, null, 2)}</pre>
        </div>
      )}
    </Drawer>
  );
}

export function AuditPage() {
  const { current } = useProject();
  const [f, setF] = useState<AuditFilters>({ limit: 50, offset: 0 });
  const [onlyProject, setOnlyProject] = useState(false);
  const [text, setText] = useState("");
  const [open, setOpen] = useState<AuditOut | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const filters: AuditFilters = { ...f, project: onlyProject && current ? current.id : undefined };
  const page = useAsync(() => api.audit(filters), [JSON.stringify(filters)]);

  useEffect(() => {
    const t = window.setTimeout(() => setF((x) => (x.q === (text.trim() || undefined) ? x : { ...x, q: text.trim() || undefined, offset: 0 })), 300);
    return () => window.clearTimeout(t);
  }, [text]);

  const exportCsv = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await api.auditExport(filters);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "vm-audit.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportError((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Журнал аудита</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn" onClick={exportCsv} disabled={exporting}>
            <Download size={15} aria-hidden="true" /> {exporting ? "Выгрузка…" : "Выгрузить CSV"}
          </button>
        </div>
      </div>
      <div className="alert alert-info">Журнал только дополняется: записи нельзя изменить или удалить.</div>
      {exportError && <ErrorAlert error={exportError} />}
      <section className="card">
        <div className="filters">
          <label className="search filters-q">
            <Search size={15} aria-hidden="true" />
            <input className="input" type="search" placeholder="Пользователь, действие, № объекта" aria-label="Поиск по журналу" value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <select className="select" aria-label="События" value={f.action ?? ""} onChange={(e) => setF((x) => ({ ...x, action: e.target.value || undefined, offset: 0 }))}>
            {GROUPS.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label}
              </option>
            ))}
          </select>
          <select className="select" aria-label="Результат" value={f.result ?? ""} onChange={(e) => setF((x) => ({ ...x, result: e.target.value || undefined, offset: 0 }))}>
            <option value="">Любой результат</option>
            <option value="ok">Успешно</option>
            <option value="denied">Отказано</option>
            <option value="error">Ошибка</option>
          </select>
          {current && (
            <button type="button" className="chip" aria-pressed={onlyProject} onClick={() => setOnlyProject((v) => !v)}>
              Только текущий проект
            </button>
          )}
        </div>
        {page.error && <ErrorAlert error={page.error} onRetry={() => void page.reload()} />}
        {page.loading && !page.data && <Loading />}
        {page.data && page.data.items.length === 0 && <Empty title="Записей не найдено" icon={<ListChecks size={28} />} />}
        {page.data && page.data.items.length > 0 && (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>Пользователь</th>
                    <th>Действие</th>
                    <th className="hide-md">Объект</th>
                    <th>Результат</th>
                  </tr>
                </thead>
                <tbody>
                  {page.data.items.map((e) => (
                    <tr key={e.id} className="clickable" onClick={() => setOpen(e)} tabIndex={0} onKeyDown={(ev) => ev.key === "Enter" && setOpen(e)}>
                      <td className="nowrap num">{fmtDateFull(e.at)}</td>
                      <td>{e.username ?? <span className="faint">система</span>}</td>
                      <td>
                        {AUDIT_ACTION_LABEL[e.action] ?? e.action}
                        <span className="faint ticket-sub mono">{e.action}</span>
                      </td>
                      <td className="hide-md mono faint">{e.object_type ? `${e.object_type} ${e.object_id ?? ""}` : "—"}</td>
                      <td>
                        <span className={`pill ${RESULT_PILL[e.result] ?? "pill-muted"}`}>{RESULT_LABEL[e.result] ?? e.result}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              total={page.data.total}
              offset={f.offset ?? 0}
              limit={f.limit ?? 50}
              onChange={(o) => setF((x) => ({ ...x, offset: o }))}
              onLimit={(l) => setF((x) => ({ ...x, limit: l, offset: 0 }))}
              label="Страницы журнала"
            />
          </>
        )}
      </section>
      {open && <Entry e={open} onClose={() => setOpen(null)} />}
    </>
  );
}
