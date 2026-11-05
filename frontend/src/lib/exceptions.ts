import type { ExceptionOut } from "../api/types";
import { plural } from "./format";

/** «через 12 дней», «сегодня», «просрочено» — до даты пересмотра. */
export function reviewLeft(ex: Pick<ExceptionOut, "days_left" | "status">): string {
  const d = ex.days_left;
  if (d === null) return "без даты пересмотра";
  if (ex.status !== "active" && ex.status !== "pending") return "";
  if (d < 0) return "дата прошла";
  if (d === 0) return "сегодня";
  return `через ${d} ${plural(d, ["день", "дня", "дней"])}`;
}
