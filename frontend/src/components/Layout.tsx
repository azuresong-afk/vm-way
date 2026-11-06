import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  CalendarClock,
  ClipboardList,
  FileText,
  FolderKanban,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Moon,
  PlugZap,
  Rocket,
  Server,
  ShieldOff,
  Sun,
  UserCheck,
  Users,
  Workflow,
  Wrench,
} from "lucide-react";
import { api } from "../api/client";
import { useAuth, type Perm } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { useTheme } from "../theme/ThemeContext";
import { ROLE_LABEL } from "../lib/labels";
import { JobsChip } from "./JobsChip";
import { QuickSearch } from "./QuickSearch";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  perm: Perm;
  admin?: boolean;
}

// Порядок пунктов — «сверху вниз» по ходу работы, как в «Сканере».
// Служебные разделы — отдельной группой «Администрирование» ниже.
const NAV: NavItem[] = [
  { to: "/", label: "Сводка", icon: <LayoutDashboard size={18} />, perm: "view" },
  { to: "/tickets", label: "Заявки", icon: <ClipboardList size={18} />, perm: "view" },
  { to: "/my", label: "Мои задачи", icon: <UserCheck size={18} />, perm: "ticket_work" },
  { to: "/windows", label: "Окна и план", icon: <CalendarClock size={18} />, perm: "view" },
  { to: "/rollouts", label: "Раскатки", icon: <Rocket size={18} />, perm: "view" },
  { to: "/exceptions", label: "Исключения", icon: <ShieldOff size={18} />, perm: "view" },
  { to: "/reports", label: "Отчёты", icon: <FileText size={18} />, perm: "view" },
  { to: "/assets", label: "Активы", icon: <Server size={18} />, perm: "view" },
  { to: "/rules", label: "Правила назначения", icon: <Workflow size={18} />, perm: "rules_manage" },
  { to: "/access", label: "Доступ к хостам", icon: <KeyRound size={18} />, perm: "credentials_manage" },
  { to: "/admin/users", label: "Пользователи и роли", icon: <Users size={18} />, perm: "users_manage", admin: true },
  { to: "/admin/projects", label: "Проекты", icon: <FolderKanban size={18} />, perm: "projects_manage", admin: true },
  { to: "/admin/sources", label: "Источники", icon: <PlugZap size={18} />, perm: "sources_manage", admin: true },
  { to: "/admin/audit", label: "Журнал аудита", icon: <ListChecks size={18} />, perm: "audit_view", admin: true },
];

function initials(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").toUpperCase() + (parts[1]?.[0] ?? "").toUpperCase();
}

function ProjectPicker() {
  const { projects, current, select } = useProject();
  if (!projects.length) return null;
  return (
    <label className="inline engagement-picker" style={{ gap: 8 }}>
      {/* подписи нет, как в «Сканере»: шапка в одну линию; имя поля — для экранных дикторов */}
      <select className="select" aria-label="Проект" value={current?.id ?? ""} onChange={(e) => select(e.target.value)}>
        {projects.map((p) => (
          <option key={p.id} value={p.id}>
            {projectLabel(p)}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Переключатель светлой и тёмной темы. */
function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return (
    <button
      type="button"
      className="btn btn-sm"
      style={{ width: "100%" }}
      onClick={toggleTheme}
      aria-label={theme === "dark" ? "Включить светлую тему" : "Включить тёмную тему"}
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
      {theme === "dark" ? "Светлая тема" : "Тёмная тема"}
    </button>
  );
}

export function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark" aria-hidden="true">
        <Wrench size={18} />
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <span className="brand-name">Устранение</span>
        <span className="brand-sub">управление уязвимостями</span>
      </div>
    </div>
  );
}

/** Сколько исключений ждёт решения текущего пользователя — счётчик у пункта «Исключения». */
function useToApprove(): number {
  const { has } = useAuth();
  const { current } = useProject();
  const location = useLocation();
  const [n, setN] = useState(0);
  const projectId = current?.id;
  const can = has("exception_approve");
  useEffect(() => {
    if (!projectId || !can) {
      setN(0);
      return;
    }
    let alive = true;
    api
      .exceptionCounts(projectId)
      .then((c) => alive && setN(c.to_approve))
      .catch(() => alive && setN(0));
    return () => {
      alive = false;
    };
  }, [projectId, can, location.pathname, location.search]);
  return n;
}

export function Layout() {
  const { me, has, logout } = useAuth();
  const toApprove = useToApprove();
  const items = NAV.filter((i) => has(i.perm));
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  const name = me?.display_name || me?.username || "";
  const roles = me?.roles.map((r) => ROLE_LABEL[r] ?? r).join(", ") || "нет ролей";
  const main = items.filter((i) => !i.admin);
  const admin = items.filter((i) => i.admin);

  return (
    <div className="shell">
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Основное меню">
        <Brand />
        {main.map((i) => (
          <NavLink key={i.to} to={i.to} end={i.to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            {i.icon}
            <span>{i.label}</span>
            {i.to === "/exceptions" && toApprove > 0 && (
              <span className="count" title="Ждут вашего утверждения">
                {toApprove}
              </span>
            )}
          </NavLink>
        ))}
        {admin.length > 0 && <div className="nav-section">Администрирование</div>}
        {admin.map((i) => (
          <NavLink key={i.to} to={i.to} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            {i.icon}
            <span>{i.label}</span>
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <div className="user-card">
            <div className="avatar" aria-hidden="true">
              {initials(name)}
            </div>
            <div className="user-meta">
              <span title={name}>{name}</span>
              <span>{roles}</span>
            </div>
            <button type="button" className="btn btn-sm btn-ghost icon-btn" style={{ marginLeft: "auto", width: 30 }} onClick={logout} aria-label="Выйти" title="Выйти">
              <LogOut size={15} />
            </button>
          </div>
          <ThemeToggle />
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <button type="button" className="btn btn-ghost icon-btn menu-btn" aria-label="Меню" onClick={() => setOpen(true)}>
            <Menu size={20} />
          </button>
          <ProjectPicker />
          <QuickSearch />
          <JobsChip />
          <span className="spacer" />
          <span className="faint hide-sm" style={{ fontSize: 12 }}>
            Только системы заказчика по договору
          </span>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
