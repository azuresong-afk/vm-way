import { api } from "../api/client";
import type { JobOut } from "../api/types";

/** Дождаться завершения фоновой задачи (импорт, проверка): опрос раз в intervalMs, не дольше timeoutMs. */
export async function waitJob(job: JobOut, { intervalMs = 2000, timeoutMs = 300_000 } = {}): Promise<JobOut> {
  let cur = job;
  const until = Date.now() + timeoutMs;
  while ((cur.status === "queued" || cur.status === "running") && Date.now() < until) {
    await new Promise((r) => setTimeout(r, intervalMs));
    cur = await api.job(cur.id);
  }
  return cur;
}

/** Сообщить плашке фоновых задач в шапке, что поставлена новая задача. */
export function notifyJobs(): void {
  window.dispatchEvent(new Event("vm:jobs"));
}
