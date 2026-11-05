import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, Check, Copy, Inbox, X } from "lucide-react";
import type { Criticality, HostStatus, Severity, TicketStatus } from "../api/types";
import { CRITICALITY_LABEL, HOST_STATUS_LABEL, HOST_STATUS_PILL, SEVERITY_LABEL, SEVERITY_SHORT, STATUS_LABEL, STATUS_PILL } from "../lib/labels";
import { bduUrl, cveUrl } from "../lib/refs";

export function SeverityBadge({ severity, short }: { severity: Severity; short?: boolean }) {
  return (
    <span className={`sev sev-${severity}`}>
      <i aria-hidden="true" />
      {short ? SEVERITY_SHORT[severity] : SEVERITY_LABEL[severity]}
    </span>
  );
}

/** Критичность актива — как в «Сканере»: те же цвета, что у уровней. */
export function CriticalityBadge({ value }: { value: Criticality }) {
  return (
    <span className={`sev sev-${value}`}>
      <i aria-hidden="true" />
      {CRITICALITY_LABEL[value]}
    </span>
  );
}

export function StatusPill({ status }: { status: TicketStatus }) {
  return <span className={`pill ${STATUS_PILL[status]}`}>{STATUS_LABEL[status]}</span>;
}

export function HostStatusPill({ status }: { status: HostStatus }) {
  return <span className={`pill ${HOST_STATUS_PILL[status]}`}>{HOST_STATUS_LABEL[status]}</span>;
}

/** Теги CVE и БДУ со ссылками на справочники; БДУ — первыми (как в «Сканере»). */
export function RefTags({ cve, bdu, limit }: { cve: string[]; bdu: string[]; limit?: number }) {
  const items = [
    ...bdu.map((id) => ({ id, url: bduUrl(id), kind: "bdu" })),
    ...cve.map((id) => ({ id, url: cveUrl(id), kind: "cve" })),
  ];
  if (!items.length) return <span className="faint">—</span>;
  const shown = limit ? items.slice(0, limit) : items;
  return (
    <span className="inline" style={{ gap: 6 }}>
      {shown.map((r) =>
        r.url ? (
          <a
            key={r.id}
            className={r.kind === "bdu" ? "tag" : "tag tag-muted"}
            href={r.url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
          >
            {r.id}
          </a>
        ) : (
          <span key={r.id} className={r.kind === "bdu" ? "tag" : "tag tag-muted"}>
            {r.id}
          </span>
        ),
      )}
      {limit && items.length > limit && <span className="faint">+{items.length - limit}</span>}
    </span>
  );
}

export function Loading({ label = "Загрузка…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorAlert({ error, onRetry }: { error: Error | string; onRetry?: () => void }) {
  return (
    <div className="alert alert-danger" role="alert">
      <AlertTriangle size={16} aria-hidden="true" />
      <span style={{ flex: 1 }}>{typeof error === "string" ? error : error.message}</span>
      {onRetry && (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Повторить
        </button>
      )}
    </div>
  );
}

export function Empty({
  title,
  children,
  icon,
  action,
}: {
  title: string;
  children?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon ?? <Inbox size={28} aria-hidden="true" />}
      <h3>{title}</h3>
      {children && <div>{children}</div>}
      {action}
    </div>
  );
}

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
}

function useInitialFocus<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    return () => prev?.focus?.();
  }, []);
  return ref;
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEscape(onClose);
  const ref = useInitialFocus<HTMLDivElement>();
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button type="button" className="btn btn-ghost icon-btn" aria-label="Закрыть" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({
  title,
  onClose,
  children,
  header,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  header?: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(onClose);
  const ref = useInitialFocus<HTMLElement>();
  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <div className="drawer-head">
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
            {header}
            <h2>{title}</h2>
          </div>
          <button type="button" className="btn btn-ghost icon-btn" aria-label="Закрыть" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </aside>
    </>
  );
}

export function Kpi({
  label,
  value,
  delta,
  tone,
  deltaTone,
}: {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
  tone?: "critical" | "warn";
  deltaTone?: "good" | "bad";
}) {
  return (
    <div className="card kpi">
      <span className="kpi-label">{label}</span>
      <span className={`kpi-value ${tone ?? ""}`}>{value}</span>
      {delta !== undefined && <span className={`kpi-delta ${deltaTone ?? ""}`}>{delta}</span>}
    </div>
  );
}

/** Блок команд с кнопкой «Копировать» (как в «Что исправить» «Сканера»). */
export function Commands({ title, lines }: { title: string; lines: string[] }) {
  const [copied, setCopied] = useState(false);
  if (!lines.length) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* буфер обмена недоступен (http без TLS) — текст можно выделить вручную */
    }
  };
  return (
    <div className="fix-cmd">
      <div className="fix-cmd-head">
        <span className="faint">{title}</span>
        <button type="button" className="btn btn-sm btn-ghost" onClick={copy} aria-label={`Копировать: ${title}`}>
          {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          {copied ? "Скопировано" : "Копировать"}
        </button>
      </div>
      <pre className="mono">{lines.join("\n")}</pre>
    </div>
  );
}

/** Подтверждение опасного действия: явный текст последствий и кнопка .btn-danger. */
export function ConfirmModal({
  title,
  children,
  confirmLabel,
  onConfirm,
  onClose,
  busy,
  error,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
  error?: string | null;
}) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-danger" onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </button>
        </>
      }
    >
      {children}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

/** Стопка уровней важности (полоса распределения), сегменты с зазором 2 px. */
export function StackBar({ counts, label }: { counts: Record<Severity, number>; label?: string }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const parts = (Object.keys(counts) as Severity[]).filter((s) => counts[s] > 0);
  return (
    <div className="stackbar" role="img" aria-label={label ?? parts.map((s) => `${SEVERITY_LABEL[s]}: ${counts[s]}`).join(", ")}>
      {total === 0 ? (
        <span style={{ flex: 1, background: "var(--surface-3)" }} />
      ) : (
        parts.map((s) => <span key={s} className={`sevbar-fill ${s}`} style={{ flex: counts[s], height: "auto" }} />)
      )}
    </div>
  );
}
