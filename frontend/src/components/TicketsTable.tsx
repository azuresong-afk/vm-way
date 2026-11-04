import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, RotateCcw } from "lucide-react";
import type { TicketBrief, TicketQuery } from "../api/types";
import { fmtDate, fmtNumber } from "../lib/format";
import { KIND_LABEL } from "../lib/labels";
import { SeverityBadge, StatusPill } from "./ui";

type SortKey = NonNullable<TicketQuery["sort"]>;

function SortTh({
  k,
  sort,
  order,
  onSort,
  children,
  right,
}: {
  k: SortKey;
  sort: SortKey;
  order: "asc" | "desc";
  onSort: (k: SortKey) => void;
  children: ReactNode;
  right?: boolean;
}) {
  const active = sort === k;
  return (
    <th className={right ? "right" : undefined} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => onSort(k)}>
        {children}
        {active && (order === "asc" ? <ArrowUp size={12} aria-hidden="true" /> : <ArrowDown size={12} aria-hidden="true" />)}
      </button>
    </th>
  );
}

/** Ход по хостам: «2 из 6» и тонкая полоса подтверждённых. */
export function HostsProgress({ t }: { t: Pick<TicketBrief, "hosts_total" | "hosts_confirmed"> }) {
  const share = t.hosts_total ? Math.round((t.hosts_confirmed / t.hosts_total) * 100) : 0;
  return (
    <span className="hosts-progress" title={`Подтверждено ${t.hosts_confirmed} из ${t.hosts_total}`}>
      <span className="num">
        {fmtNumber(t.hosts_confirmed)} из {fmtNumber(t.hosts_total)}
      </span>
      <span className="hosts-progress-bar" aria-hidden="true">
        <span style={{ width: `${share}%` }} />
      </span>
    </span>
  );
}

export function TicketsTable({
  items,
  sort,
  order,
  onSort,
  onOpen,
  selected,
  onSelect,
  activeId,
}: {
  items: TicketBrief[];
  sort: SortKey;
  order: "asc" | "desc";
  onSort: (k: SortKey) => void;
  onOpen: (t: TicketBrief) => void;
  selected?: Set<number>;
  onSelect?: (ids: number[], on: boolean) => void;
  activeId?: number | null;
}) {
  const allOn = !!selected && items.length > 0 && items.every((t) => selected.has(t.id));
  return (
    <div className="table-wrap">
      <table className="table tickets-table">
        <thead>
          <tr>
            {onSelect && (
              <th style={{ width: 34 }}>
                <input
                  type="checkbox"
                  className="cb"
                  aria-label="Выбрать все на странице"
                  checked={allOn}
                  onChange={(e) => onSelect(items.map((t) => t.id), e.target.checked)}
                />
              </th>
            )}
            <th style={{ width: 56 }}>№</th>
            <SortTh k="title" sort={sort} order={order} onSort={onSort}>
              Заявка
            </SortTh>
            <SortTh k="severity" sort={sort} order={order} onSort={onSort}>
              Уровень
            </SortTh>
            <SortTh k="priority" sort={sort} order={order} onSort={onSort}>
              Приоритет
            </SortTh>
            <th>Статус</th>
            <th className="hide-md">Исполнитель</th>
            <SortTh k="hosts" sort={sort} order={order} onSort={onSort}>
              Хосты
            </SortTh>
            <SortTh k="updated" sort={sort} order={order} onSort={onSort} right>
              Изменена
            </SortTh>
          </tr>
        </thead>
        <tbody>
          {items.map((t) => (
            <tr
              key={t.id}
              className={`clickable${selected?.has(t.id) || activeId === t.id ? " selected" : ""}`}
              onClick={() => onOpen(t)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onOpen(t);
              }}
              tabIndex={0}
              aria-label={`Заявка №${t.id}: ${t.title}`}
            >
              {onSelect && (
                <td onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    className="cb"
                    aria-label={`Выбрать заявку №${t.id}`}
                    checked={selected?.has(t.id) ?? false}
                    onChange={(e) => onSelect([t.id], e.target.checked)}
                  />
                </td>
              )}
              <td className="mono faint">{t.id}</td>
              <td className="ticket-cell" style={{ minWidth: 320 }}>
                <span className="ticket-title">{t.title}</span>
                <span className="faint ticket-sub">
                  {[KIND_LABEL[t.kind] ?? t.kind, t.os, t.cves.slice(0, 2).join(", ")].filter(Boolean).join(" · ")}
                  {t.reboot && <span className="tag tag-muted">перезагрузка</span>}
                </span>
              </td>
              <td>
                <SeverityBadge severity={t.severity} />
                {t.severity_overridden && (
                  <span className="faint" title="Уровень переопределён руководителем" style={{ marginLeft: 4 }}>
                    *
                  </span>
                )}
              </td>
              <td className="num">{t.priority.rank ? `#${t.priority.rank}` : <span className="faint">—</span>}</td>
              <td>
                <span className="inline" style={{ gap: 6, flexWrap: "nowrap" }}>
                  <StatusPill status={t.status} />
                  {t.is_regression && t.status !== "regression" && (
                    <span title="Уязвимость появилась снова после исправления" aria-label="Регрессия" className="faint">
                      <RotateCcw size={13} aria-hidden="true" />
                    </span>
                  )}
                </span>
              </td>
              <td className="hide-md nowrap">{t.assignee ? t.assignee.display_name : <span className="faint">не назначена</span>}</td>
              <td>
                <HostsProgress t={t} />
              </td>
              <td className="right nowrap faint">{fmtDate(t.updated_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
