import { useState } from "react";
import { FolderPlus, Pencil } from "lucide-react";
import { api } from "../../api/client";
import type { ProjectIn, ProjectOut } from "../../api/types";
import { useProject } from "../../auth/ProjectContext";
import { Empty, ErrorAlert, Loading, Modal } from "../../components/ui";
import { fmtDay } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

function ProjectModal({ project, onClose, onDone }: { project: ProjectOut | null; onClose: () => void; onDone: () => void }) {
  const [d, setD] = useState<ProjectIn>({
    name: project?.name ?? "",
    client: project?.client ?? "",
    contract_ref: project?.contract_ref ?? "",
    period_from: project?.period_from ?? null,
    period_to: project?.period_to ?? null,
    status: project?.status ?? "active",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const up = (patch: Partial<ProjectIn>) => setD((x) => ({ ...x, ...patch }));
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const data = { ...d, name: d.name.trim(), period_from: d.period_from || null, period_to: d.period_to || null };
      if (project) await api.updateProject(project.id, data);
      else await api.createProject({ ...data, status: undefined });
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={project ? `Проект «${project.name}»` : "Новый проект"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy || !d.name.trim()}>
            {busy ? "Сохранение…" : project ? "Сохранить" : "Создать"}
          </button>
        </>
      }
    >
      <span className="muted">Проект — это договор на работы с заказчиком. Привязка к проекту «Сканера» — в разделе «Источники».</span>
      <div className="grid-2">
        <label className="field">
          <span>Название</span>
          <input className="input" value={d.name} onChange={(e) => up({ name: e.target.value })} />
        </label>
        <label className="field">
          <span>Заказчик</span>
          <input className="input" value={d.client} onChange={(e) => up({ client: e.target.value })} />
        </label>
        <label className="field">
          <span>Номер договора</span>
          <input className="input" value={d.contract_ref} onChange={(e) => up({ contract_ref: e.target.value })} />
        </label>
        <span />
        <label className="field">
          <span>Начало работ</span>
          <input className="input" type="date" value={d.period_from ?? ""} onChange={(e) => up({ period_from: e.target.value })} />
        </label>
        <label className="field">
          <span>Окончание работ</span>
          <input className="input" type="date" value={d.period_to ?? ""} onChange={(e) => up({ period_to: e.target.value })} />
        </label>
      </div>
      {project && (
        <label className="check">
          <input type="checkbox" checked={d.status === "archived"} onChange={(e) => up({ status: e.target.checked ? "archived" : "active" })} />
          <span>
            <b>В архиве</b>
            <small>Архивный проект пропадает из выбора в верхней панели; данные и журнал сохраняются.</small>
          </span>
        </label>
      )}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

export function ProjectsPage() {
  const { reload } = useProject();
  const list = useAsync(() => api.projects(true), []);
  const [edit, setEdit] = useState<ProjectOut | "new" | null>(null);
  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Проекты</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => setEdit("new")}>
            <FolderPlus size={15} aria-hidden="true" /> Создать проект
          </button>
        </div>
      </div>
      <section className="card">
        {list.error && <ErrorAlert error={list.error} onRetry={() => void list.reload()} />}
        {list.loading && !list.data && <Loading />}
        {list.data && list.data.length === 0 && <Empty title="Проектов нет">Создайте первый проект — договор на работы с заказчиком.</Empty>}
        {list.data && list.data.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Проект</th>
                  <th>Договор</th>
                  <th>Срок работ</th>
                  <th>Состояние</th>
                  <th className="right">Действия</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((p) => (
                  <tr key={p.id} className={p.status === "archived" ? "is-fp" : undefined}>
                    <td>
                      <span className="ticket-title">{p.name}</span>
                      {p.client && <span className="faint ticket-sub">{p.client}</span>}
                    </td>
                    <td>{p.contract_ref || <span className="faint">—</span>}</td>
                    <td className="nowrap">
                      {p.period_from || p.period_to ? `${fmtDay(p.period_from)} — ${fmtDay(p.period_to)}` : <span className="faint">не указан</span>}
                    </td>
                    <td>{p.status === "active" ? <span className="pill pill-ok">Активен</span> : <span className="pill pill-muted">В архиве</span>}</td>
                    <td className="right">
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => setEdit(p)}>
                        <Pencil size={14} aria-hidden="true" /> Изменить
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
        <ProjectModal
          project={edit === "new" ? null : edit}
          onClose={() => setEdit(null)}
          onDone={() => {
            setEdit(null);
            void list.reload();
            void reload();
          }}
        />
      )}
    </>
  );
}
