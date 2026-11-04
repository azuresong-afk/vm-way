import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, ClipboardList, Search, Server, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import type { SearchOut, Severity } from "../api/types";
import { useAuth, type Perm } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { useTheme } from "../theme/ThemeContext";
import { plural } from "../lib/format";
import { SEVERITY_SHORT } from "../lib/labels";

/** Строка результата: что показать и что сделать по Enter. */
interface Item {
  id: string;
  icon: ReactNode;
  title: string;
  sub: string;
  mono?: boolean;
  severity?: Severity | null;
  badge?: string;
  hint: string;
  to?: string;
  run?: () => void;
}

interface Group {
  title: string;
  count: number;
  items: Item[];
}

interface Command {
  id: string;
  title: string;
  words: string;
  perm: Perm;
  to?: string;
  theme?: boolean;
}

/** Действия палитры: переходы по разделам и переключение темы. */
const COMMANDS: Command[] = [
  { id: "summary", title: "Открыть «Сводку»", words: "сводка главная обзор", perm: "view", to: "/" },
  { id: "tickets", title: "Открыть «Заявки»", words: "заявки список таблица", perm: "view", to: "/tickets" },
  { id: "open", title: "Открытые заявки без исполнителя", words: "свободные новые назначить без исполнителя", perm: "view", to: "/tickets?assignee=none" },
  { id: "my", title: "Открыть «Мои задачи»", words: "мои задачи исполнитель", perm: "ticket_work", to: "/my" },
  { id: "fixed", title: "Заявки, ждущие проверки", words: "исправлено проверка ждёт", perm: "view", to: "/tickets?status=fixed" },
  { id: "users", title: "Пользователи и роли", words: "пользователи роли доступ", perm: "users_manage", to: "/admin/users" },
  { id: "projects", title: "Проекты", words: "проекты договоры", perm: "projects_manage", to: "/admin/projects" },
  { id: "sources", title: "Источники", words: "источники сканер подключение привязка", perm: "sources_manage", to: "/admin/sources" },
  { id: "audit", title: "Журнал аудита", words: "журнал аудит события", perm: "audit_view", to: "/admin/audit" },
  { id: "theme", title: "Переключить тему", words: "тема светлая тёмная темная оформление", perm: "view", theme: true },
];

const ru = (n: number) => n.toLocaleString("ru-RU");

/** Подсветка совпадения (без учёта регистра) — первое вхождение. */
function Hit({ text, q }: { text: string; q: string }) {
  const i = q ? text.toLocaleLowerCase("ru-RU").indexOf(q.toLocaleLowerCase("ru-RU")) : -1;
  if (i < 0) return <>{text}</>;
  return (
    <>
      {text.slice(0, i)}
      <mark>{text.slice(i, i + q.length)}</mark>
      {text.slice(i + q.length)}
    </>
  );
}

function toGroups(r: SearchOut | null, commands: Item[]): Group[] {
  const groups: Group[] = [];
  if (r) {
    groups.push({
      title: "Заявки",
      count: r.counts.tickets,
      items: r.tickets.map((t) => ({
        id: `t:${t.id}`,
        icon: <ClipboardList size={15} />,
        title: `№${t.id} · ${t.title}`,
        sub: [t.status_label, t.os].filter(Boolean).join(" · "),
        severity: t.severity,
        hint: "Заявка",
        to: t.url,
      })),
    });
    groups.push({
      title: "Хосты",
      count: r.counts.hosts,
      items: r.hosts.map((h) => ({
        id: `h:${h.project_id}:${h.host}`,
        icon: <Server size={15} />,
        title: h.host,
        sub: h.open ? `${ru(h.open)} ${plural(h.open, ["открытая уязвимость", "открытые уязвимости", "открытых уязвимостей"])}` : "открытых уязвимостей нет",
        mono: true,
        severity: h.max_severity,
        badge: h.open ? `${ru(h.open)} уязв.` : undefined,
        hint: "Заявки хоста",
        to: h.url,
      })),
    });
    groups.push({
      title: "CVE и БДУ",
      count: r.counts.vulns,
      items: r.vulns.map((v) => {
        const ids = [...new Set([v.id, ...v.cves, ...v.bdu_ids])];
        return {
          id: `v:${v.project_id}:${v.id}`,
          icon: <ShieldAlert size={15} />,
          title: `${ids[0]} · ${v.title}`,
          sub: [...ids.slice(1), `${ru(v.host_count)} ${plural(v.host_count, ["хост", "хоста", "хостов"])}`].join(" · "),
          mono: true,
          severity: v.severity,
          hint: v.ticket_id ? "Заявка" : "Заявки",
          to: v.ticket_id ? `/tickets/${v.ticket_id}?project=${v.project_id}` : v.url,
        };
      }),
    });
  }
  groups.push({ title: "Действия", count: commands.length, items: commands });
  return groups.filter((g) => g.items.length > 0);
}

/**
 * Быстрый поиск: поле в верхней панели и палитра по Ctrl+K (⌘K на macOS) с любой страницы.
 * Ищет заявки (по номеру и названию), хосты, CVE и БДУ текущего проекта, а также действия
 * (переходы по разделам). ↑/↓ — выбор, Enter — открыть.
 */
export function QuickSearch() {
  const { has } = useAuth();
  const { current } = useProject();
  const [open, setOpen] = useState(false);
  const enabled = has("view") && !!current;

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K" || e.code === "KeyK")) {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);

  if (!enabled) return null;
  return (
    <>
      <button type="button" className="qs-trigger" onClick={() => setOpen(true)} aria-label="Поиск по проекту (Ctrl+K)" aria-haspopup="dialog">
        <Search size={15} aria-hidden="true" />
        <span className="qs-trigger-text">Заявка, хост, CVE, БДУ…</span>
        <kbd className="hide-sm">Ctrl K</kbd>
      </button>
      {open && <Palette projectId={current!.id} project={projectLabel(current!)} onClose={() => setOpen(false)} />}
    </>
  );
}

function Palette({ projectId, project, onClose }: { projectId: string; project: string; onClose: () => void }) {
  const navigate = useNavigate();
  const { has } = useAuth();
  const { toggleTheme } = useTheme();
  const [text, setText] = useState("");
  const [data, setData] = useState<SearchOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const q = text.trim();

  useEffect(() => {
    const prev = document.activeElement;
    inputRef.current?.focus();
    return () => (prev as HTMLElement | null)?.focus?.();
  }, []);

  useEffect(() => {
    if (!q) {
      setData(null);
      setError(null);
      setLoading(false);
      return;
    }
    const ctl = new AbortController();
    setLoading(true);
    const t = window.setTimeout(() => {
      api
        .search(q, projectId, { signal: ctl.signal })
        .then((r) => {
          setData(r);
          setError(null);
          setSel(0);
        })
        .catch((e: Error) => {
          if (!ctl.signal.aborted) setError(e.message);
        })
        .finally(() => {
          if (!ctl.signal.aborted) setLoading(false);
        });
    }, 180);
    return () => {
      ctl.abort();
      window.clearTimeout(t);
    };
  }, [projectId, q]);

  const commands = useMemo<Item[]>(() => {
    const needle = q.toLocaleLowerCase("ru-RU");
    return COMMANDS.filter((c) => has(c.perm))
      .filter((c) => !needle || `${c.title} ${c.words}`.toLocaleLowerCase("ru-RU").includes(needle))
      .map((c) => ({
        id: `cmd:${c.id}`,
        icon: <ArrowRight size={15} />,
        title: c.title,
        sub: c.theme ? "светлая или тёмная" : (c.to ?? ""),
        hint: c.theme ? "Переключить" : "Перейти",
        to: c.to,
        run: c.theme ? toggleTheme : undefined,
      }));
  }, [q, has, toggleTheme]);

  const shown = q ? data && data.q === q : true;
  const groups = useMemo(() => toGroups(shown && q ? data : null, commands), [data, commands, shown, q]);
  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  const active = flat[Math.min(sel, flat.length - 1)];

  useEffect(() => {
    if (!active) return;
    listRef.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(active.id)}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [active]);

  const run = useCallback(
    (it: Item | undefined) => {
      if (!it) return;
      onClose();
      if (it.run) it.run();
      else if (it.to) navigate(it.to);
    },
    [navigate, onClose],
  );

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => (flat.length ? (Math.min(s, flat.length - 1) + 1) % flat.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => (flat.length ? (Math.min(s, flat.length - 1) - 1 + flat.length) % flat.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(active);
    } else if (e.key === "Tab") {
      e.preventDefault(); // фокус остаётся в поле: выбор — стрелками
    }
  };

  const total = data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="modal-scrim qs-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="qs" role="dialog" aria-modal="true" aria-label="Быстрый поиск" onKeyDown={onKeyDown}>
        <div className="qs-head">
          <Search size={18} aria-hidden="true" />
          <input
            ref={inputRef}
            type="search"
            className="qs-input"
            placeholder="№ заявки, название, хост, CVE, БДУ или действие"
            aria-label="Поиск по заявкам, хостам, CVE, БДУ и действиям"
            role="combobox"
            aria-expanded={flat.length > 0}
            aria-controls="qs-list"
            aria-activedescendant={active ? `qs-${active.id}` : undefined}
            autoComplete="off"
            spellCheck={false}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <span className="qs-scope hide-sm" title="Поиск идёт по текущему проекту">
            {project}
          </span>
          <kbd>Esc</kbd>
        </div>
        <div className="qs-list" id="qs-list" role="listbox" aria-label="Результаты" ref={listRef}>
          {error && <div className="qs-empty qs-error">{error}</div>}
          {q && shown && !error && flat.length === 0 && <div className="qs-empty">Ничего не найдено по «{q}»</div>}
          {q && !shown && loading && !error && <div className="qs-empty">Поиск…</div>}
          {groups.map((g) => (
            <div key={g.title} role="group" aria-label={g.title}>
              <div className="qs-group">
                <span>{g.title}</span>
                <span>{g.count > g.items.length ? `${g.items.length} из ${ru(g.count)}` : ru(g.count)}</span>
              </div>
              {g.items.map((it) => (
                <div
                  key={it.id}
                  id={`qs-${it.id}`}
                  data-id={it.id}
                  role="option"
                  aria-selected={it === active}
                  className="qs-row"
                  onMouseMove={() => it !== active && setSel(flat.indexOf(it))}
                  onClick={() => run(it)}
                >
                  <span className="qs-icon" aria-hidden="true">
                    {it.icon}
                  </span>
                  <span className="qs-text">
                    <span className="qs-title">
                      <Hit text={it.title} q={q} />
                    </span>
                    <span className={`qs-sub${it.mono ? " mono" : ""}`}>
                      <Hit text={it.sub} q={q} />
                    </span>
                  </span>
                  {it.severity && <span className={`qs-badge qs-sev-${it.severity}`}>{it.badge ?? SEVERITY_SHORT[it.severity]}</span>}
                  {!it.severity && it.badge && <span className="qs-badge qs-acc">{it.badge}</span>}
                  <span className="qs-hint">{it.hint}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="qs-foot">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> выбрать
          </span>
          <span>
            <kbd>Enter</kbd> открыть
          </span>
          {data && q && shown && (
            <span className="qs-foot-scope">
              {ru(total)} {plural(total, ["совпадение", "совпадения", "совпадений"])}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
