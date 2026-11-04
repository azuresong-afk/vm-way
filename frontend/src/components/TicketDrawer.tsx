import { Link } from "react-router-dom";
import { ExternalLink, Maximize2 } from "lucide-react";
import { api } from "../api/client";
import { fmtDate, fmtNumber } from "../lib/format";
import { KIND_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { HostsProgress } from "./TicketsTable";
import { TicketActions } from "./TicketActions";
import { Commands, Drawer, ErrorAlert, HostStatusPill, Loading, RefTags, SeverityBadge, StatusPill } from "./ui";

/** Шторка заявки: главное о заявке и действия без ухода со списка. */
export function TicketDrawer({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const t = useAsync(() => api.ticket(id), [id]);
  const d = t.data;
  const changed = () => {
    void t.reload();
    onChanged();
  };
  return (
    <Drawer
      title={d ? d.title : `Заявка №${id}`}
      onClose={onClose}
      header={
        d && (
          <span className="inline" style={{ gap: 8 }}>
            <span className="mono faint">№{d.id}</span>
            <StatusPill status={d.status} />
            <SeverityBadge severity={d.severity} />
          </span>
        )
      }
      footer={
        <Link to={`/tickets/${id}`} className="btn btn-sm">
          <Maximize2 size={15} aria-hidden="true" /> Открыть заявку
        </Link>
      }
    >
      {t.error && <ErrorAlert error={t.error} onRetry={() => void t.reload()} />}
      {t.loading && !d && <Loading />}
      {d && (
        <>
          <TicketActions t={d} onChanged={changed} compact />
          <dl className="kv">
            <dt>Исполнитель</dt>
            <dd>{d.assignee ? d.assignee.display_name : <span className="faint">не назначена</span>}</dd>
            <dt>Вид</dt>
            <dd>
              {d.action.kind_label ?? KIND_LABEL[d.kind] ?? d.kind}
              {d.os && <span className="faint">· {d.os}</span>}
            </dd>
            <dt>Хосты</dt>
            <dd>
              <HostsProgress t={d} />
            </dd>
            <dt>Уязвимости</dt>
            <dd>
              {fmtNumber(d.vulns_open)} открыто из {fmtNumber(d.vulns_total)}
            </dd>
            <dt>CVE и БДУ</dt>
            <dd>
              <RefTags cve={d.action.cves ?? d.cves} bdu={d.action.bdu_ids ?? []} limit={6} />
            </dd>
            <dt>Изменена</dt>
            <dd>{fmtDate(d.updated_at)}</dd>
            {d.evidence && (
              <>
                <dt>Доказательство</dt>
                <dd>
                  {d.evidence.url ? (
                    <a href={d.evidence.url} target="_blank" rel="noopener noreferrer">
                      Прогон №{d.evidence.scanner_run_id} <ExternalLink size={12} aria-hidden="true" />
                    </a>
                  ) : (
                    <>Прогон №{d.evidence.scanner_run_id}</>
                  )}
                  <span className="faint">{fmtDate(d.evidence.finished_at)}</span>
                </dd>
              </>
            )}
          </dl>
          {(d.action.commands?.length ?? 0) > 0 && <Commands title={d.os ? `Команды · ${d.os}` : "Команды"} lines={d.action.commands ?? []} />}
          <div className="stack" style={{ gap: 0 }}>
            <h3 style={{ marginBottom: 8 }}>Хосты</h3>
            {d.hosts.map((h) => (
              <div key={h.id} className="list-row" style={{ alignItems: "flex-start" }}>
                <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                  <span className="mono">{h.host}</span>
                  {h.reason && <span className="faint" style={{ fontSize: 12.5 }}>{h.reason}</span>}
                </span>
                <HostStatusPill status={h.status} />
              </div>
            ))}
          </div>
        </>
      )}
    </Drawer>
  );
}
