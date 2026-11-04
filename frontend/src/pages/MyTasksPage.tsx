import { useState } from "react";
import { Link } from "react-router-dom";
import { Hand } from "lucide-react";
import { api } from "../api/client";
import { useProject } from "../auth/ProjectContext";
import { HostsProgress } from "../components/TicketsTable";
import { Empty, ErrorAlert, Loading, SeverityBadge } from "../components/ui";
import { fmtNumber } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { TicketsPage } from "./TicketsPage";

/** Свободные открытые заявки по приоритету — взять одним нажатием. */
function FreeTickets({ onTaken }: { onTaken: () => void }) {
  const { current } = useProject();
  const projectId = current!.id;
  const free = useAsync(() => api.tickets(projectId, { state: "open", assignee: "none", sort: "priority", limit: 8 }), [projectId]);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const take = async (id: number) => {
    setBusy(id);
    setError(null);
    try {
      await api.take(id);
      await free.reload();
      onTaken();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  return (
    <section className="card" aria-labelledby="free-head">
      <div className="card-head">
        <h2 id="free-head">Свободные заявки</h2>
        {free.data && free.data.total > free.data.items.length && (
          <Link to="/tickets?assignee=none" style={{ fontSize: 13 }}>
            Все {fmtNumber(free.data.total)}
          </Link>
        )}
      </div>
      {error && (
        <div style={{ padding: "0 20px 13px" }}>
          <ErrorAlert error={error} />
        </div>
      )}
      {free.error && <ErrorAlert error={free.error} onRetry={() => void free.reload()} />}
      {free.loading && !free.data && <Loading />}
      {free.data && free.data.items.length === 0 && <Empty title="Свободных заявок нет">Все открытые заявки уже назначены.</Empty>}
      {free.data && free.data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table tickets-table">
            <thead>
              <tr>
                <th style={{ width: 56 }}>№</th>
                <th>Заявка</th>
                <th>Уровень</th>
                <th>Хосты</th>
                <th className="right">Действие</th>
              </tr>
            </thead>
            <tbody>
              {free.data.items.map((t) => (
                <tr key={t.id}>
                  <td className="mono faint">{t.id}</td>
                  <td className="ticket-cell" style={{ minWidth: 220 }}>
                    <Link to={`/tickets/${t.id}`} className="ticket-title">
                      {t.title}
                    </Link>
                    {t.os && <span className="faint ticket-sub">{t.os}</span>}
                  </td>
                  <td>
                    <SeverityBadge severity={t.severity} />
                  </td>
                  <td>
                    <HostsProgress t={t} />
                  </td>
                  <td className="right">
                    <button type="button" className="btn btn-sm" disabled={busy !== null} onClick={() => void take(t.id)}>
                      <Hand size={15} aria-hidden="true" /> {busy === t.id ? "…" : "Взять"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** «Мои задачи» исполнителя: его открытые заявки и свободные, которые можно взять. */
export function MyTasksPage() {
  const [rev, setRev] = useState(0);
  return (
    <>
      <TicketsPage key={rev} mine />
      <FreeTickets onTaken={() => setRev((r) => r + 1)} />
    </>
  );
}
