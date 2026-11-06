import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { FolderX, Lock } from "lucide-react";
import { useAuth, type Perm } from "./auth/AuthContext";
import { ProjectProvider, useProject } from "./auth/ProjectContext";
import { Layout } from "./components/Layout";
import { Empty, ErrorAlert, Loading } from "./components/ui";
import { AccessPage } from "./pages/AccessPage";
import { AssetsPage } from "./pages/AssetsPage";
import { ExceptionsPage } from "./pages/ExceptionsPage";
import { LoginPage } from "./pages/LoginPage";
import { MyTasksPage } from "./pages/MyTasksPage";
import { ReportsPage } from "./pages/ReportsPage";
import { RolloutPage } from "./pages/RolloutPage";
import { RolloutsPage } from "./pages/RolloutsPage";
import { RulesPage } from "./pages/RulesPage";
import { SummaryPage } from "./pages/SummaryPage";
import { TicketPage } from "./pages/TicketPage";
import { TicketsPage } from "./pages/TicketsPage";
import { WindowsPage } from "./pages/WindowsPage";
import { AuditPage } from "./pages/admin/AuditPage";
import { ProjectsPage } from "./pages/admin/ProjectsPage";
import { SourcesPage } from "./pages/admin/SourcesPage";
import { UsersPage } from "./pages/admin/UsersPage";

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <Loading label="Проверка сессии…" />;
  if (!me) {
    const next = location.pathname + location.search;
    return <Navigate to={next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <>{children}</>;
}

const PERM_TITLE: Partial<Record<Perm, string>> = {
  view: "просмотр",
  ticket_work: "работа с заявками",
  users_manage: "управление пользователями",
  projects_manage: "управление проектами",
  sources_manage: "управление источниками",
  audit_view: "журнал аудита",
};

function RequirePerm({ perm, children }: { perm: Perm; children: ReactNode }) {
  const { has } = useAuth();
  if (!has(perm)) {
    return (
      <div className="card">
        <Empty title="Нет доступа" icon={<Lock size={28} />}>
          Для этого раздела нужно право «{PERM_TITLE[perm] ?? perm}». Обратитесь к администратору.
        </Empty>
      </div>
    );
  }
  return <>{children}</>;
}

/** Рабочие экраны требуют выбранного проекта. */
function RequireProject({ children }: { children: ReactNode }) {
  const { current, loading, error, reload } = useProject();
  const { has } = useAuth();
  if (loading) return <Loading />;
  if (error) return <ErrorAlert error={error} onRetry={() => void reload()} />;
  if (!current) {
    return (
      <div className="card">
        <Empty title="Проектов пока нет" icon={<FolderX size={28} />}>
          {has("projects_manage")
            ? "Создайте проект в разделе «Администрирование → Проекты» и привяжите его к «Сканеру»."
            : "Попросите администратора создать проект и привязать его к «Сканеру»."}
        </Empty>
      </div>
    );
  }
  return <>{children}</>;
}

/** Стартовая страница по правам: у администратора без рабочих ролей — пользователи. */
function Home() {
  const { has } = useAuth();
  if (has("view") && !has("users_manage")) return <RequireProject><SummaryPage /></RequireProject>;
  if (has("users_manage")) return <Navigate to="/admin/users" replace />;
  return (
    <div className="card">
      <Empty title="Нет назначенных ролей" icon={<Lock size={28} />}>
        Обратитесь к администратору, чтобы получить доступ.
      </Empty>
    </div>
  );
}

const work = (perm: Perm, el: ReactNode) => (
  <RequirePerm perm={perm}>
    <RequireProject>{el}</RequireProject>
  </RequirePerm>
);

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <ProjectProvider>
              <Layout />
            </ProjectProvider>
          </RequireAuth>
        }
      >
        <Route index element={<Home />} />
        <Route path="summary" element={work("view", <SummaryPage />)} />
        <Route path="tickets" element={work("view", <TicketsPage />)} />
        <Route path="tickets/:id" element={<RequirePerm perm="view"><TicketPage /></RequirePerm>} />
        <Route path="my" element={work("ticket_work", <MyTasksPage />)} />
        <Route path="windows" element={work("view", <WindowsPage />)} />
        <Route path="rollouts" element={work("view", <RolloutsPage />)} />
        <Route path="rollouts/:id" element={<RequirePerm perm="view"><RolloutPage /></RequirePerm>} />
        <Route path="exceptions" element={work("view", <ExceptionsPage />)} />
        <Route path="reports" element={work("view", <ReportsPage />)} />
        <Route path="assets" element={work("view", <AssetsPage />)} />
        <Route path="rules" element={work("view", <RulesPage />)} />
        <Route path="access" element={work("view", <AccessPage />)} />
        <Route path="admin/users" element={<RequirePerm perm="users_manage"><UsersPage /></RequirePerm>} />
        <Route path="admin/projects" element={<RequirePerm perm="projects_manage"><ProjectsPage /></RequirePerm>} />
        <Route path="admin/sources" element={<RequirePerm perm="sources_manage"><SourcesPage /></RequirePerm>} />
        <Route path="admin/audit" element={<RequirePerm perm="audit_view"><AuditPage /></RequirePerm>} />
        <Route path="*" element={<div className="card"><Empty title="Страница не найдена" /></div>} />
      </Route>
    </Routes>
  );
}
