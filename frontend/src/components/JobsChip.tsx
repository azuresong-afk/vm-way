import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { JobOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useProject } from "../auth/ProjectContext";
import { plural } from "../lib/format";

/** Как часто спрашивать: пока задачи идут — чаще, без задач — реже. */
const POLL_ACTIVE_MS = 4000;
const POLL_IDLE_MS = 20000;

const KIND_LABEL: Record<string, string> = {
  import_run: "Импорт прогона",
  import_pending: "Импорт прогонов",
  poll_source: "Опрос «Сканера»",
  verify: "Повторная проверка",
};

/** Фоновые задачи текущего проекта (импорт, повторная проверка) — плашка в шапке. */
export function JobsChip() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current?.id ?? null;
  const [jobs, setJobs] = useState<JobOut[]>([]);
  const canView = has("view");

  useEffect(() => {
    setJobs([]);
    if (projectId == null || !canView) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let active = false;
    const tick = async () => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") {
        try {
          const page = await api.jobs(projectId, true);
          if (!alive) return;
          setJobs(page.items);
          active = page.items.length > 0;
        } catch {
          // сеть моргнула — плашка останется прежней до следующего опроса
        }
      }
      if (alive) timer = setTimeout(tick, active ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    };
    void tick();
    // Кнопки «Импортировать» и «Проверить» сообщают о новой задаче — опросить сразу.
    const kick = () => {
      if (timer) clearTimeout(timer);
      void tick();
    };
    window.addEventListener("vm:jobs", kick);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
      window.removeEventListener("vm:jobs", kick);
    };
  }, [projectId, canView]);

  if (!jobs.length) return null;
  const job = jobs.find((j) => j.status === "running") ?? jobs[0];
  const others = jobs.length - 1;
  const main = job.title || KIND_LABEL[job.kind] || "Фоновая задача";
  const state = job.status === "running" ? "идёт" : "в очереди";
  const title = [main, state, others > 0 ? `ещё ${others} ${plural(others, ["задача", "задачи", "задач"])}` : null]
    .filter(Boolean)
    .join(" · ");
  return (
    <span className="run-chip" title={title} aria-label={title} role="status">
      <span className={`run-chip-dot ${job.status === "running" ? "running" : ""}`} aria-hidden="true" />
      <span className="run-chip-text">{main}</span>
      <span className="run-chip-short">{state}</span>
      {others > 0 && <span className="run-chip-more">+{others}</span>}
    </span>
  );
}
