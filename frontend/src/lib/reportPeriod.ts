import type { ProjectOut } from "../api/types";

/** Период отчёта (задача 3.1): пресеты экрана «Отчёты». */
export type Preset = "month" | "3m" | "year" | "contract" | "custom";

/** Дата в формате YYYY-MM-DD по местному времени браузера. */
export function isoDay(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function minusDays(day: string, n: number): string {
  const [y, m, d] = day.split("-").map(Number);
  return isoDay(new Date(y, m - 1, d - n));
}

/** Границы периода по пресету. «Срок договора» — даты проекта, конец не позже сегодняшнего дня. */
export function presetRange(preset: Exclude<Preset, "custom">, today: string, project: ProjectOut): { from: string; to: string } {
  if (preset === "contract" && project.period_from) {
    const to = project.period_to && project.period_to < today ? project.period_to : today;
    return { from: project.period_from < to ? project.period_from : to, to };
  }
  const back = preset === "month" ? 29 : preset === "year" ? 364 : 90;
  return { from: minusDays(today, back), to: today };
}
