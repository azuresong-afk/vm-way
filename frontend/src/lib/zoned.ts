import type { WindowOut } from "../api/types";

// Время в часовом поясе окна обслуживания: окна задаются по часам заказчика
// («вторник 22:00 по Москве»), а не по часам браузера.

export const TIMEZONES = [
  "Europe/Kaliningrad",
  "Europe/Moscow",
  "Europe/Samara",
  "Asia/Yekaterinburg",
  "Asia/Omsk",
  "Asia/Novosibirsk",
  "Asia/Krasnoyarsk",
  "Asia/Irkutsk",
  "Asia/Yakutsk",
  "Asia/Vladivostok",
  "Asia/Magadan",
  "Asia/Kamchatka",
  "UTC",
];

export const WEEKDAYS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];

function parts(d: Date, tz: string): Record<string, number> {
  const f = new Intl.DateTimeFormat("en-GB", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const out: Record<string, number> = {};
  for (const p of f.formatToParts(d)) if (p.type !== "literal") out[p.type] = Number(p.value);
  return out;
}

/** Смещение пояса относительно UTC в миллисекундах в момент `d`. */
function offsetMs(d: Date, tz: string): number {
  const p = parts(d, tz);
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return asUtc - Math.floor(d.getTime() / 1000) * 1000;
}

/** «2026-11-10T22:00» в поясе `tz` → ISO в UTC. */
export function zonedToIso(local: string, tz: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(local);
  if (!m) return null;
  const guess = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  let t = guess - offsetMs(new Date(guess), tz);
  // Повтор на случай перехода на летнее время между догадкой и ответом.
  t = guess - offsetMs(new Date(t), tz);
  return new Date(t).toISOString();
}

/** ISO → «2026-11-10T22:00» в поясе `tz` (для поля datetime-local). */
export function isoToZoned(iso: string | null | undefined, tz: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = parts(d, tz);
  const z = (n: number) => String(n).padStart(2, "0");
  return `${p.year}-${z(p.month)}-${z(p.day)}T${z(p.hour)}:${z(p.minute)}`;
}

/** «вт 10.11 22:00» в поясе окна. */
export function fmtZoned(iso: string | null | undefined, tz: string, withDay = true): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const p = parts(d, tz);
  const z = (n: number) => String(n).padStart(2, "0");
  const wd = WEEKDAYS[(new Date(Date.UTC(p.year, p.month - 1, p.day)).getUTCDay() + 6) % 7];
  const time = `${z(p.hour)}:${z(p.minute)}`;
  return withDay ? `${wd} ${z(p.day)}.${z(p.month)} ${time}` : time;
}

/** Интервал даты окна: «вт 10.11 22:00–02:00» или с датой конца, если окно длиннее суток. */
export function fmtRange(start: string, end: string, tz: string): string {
  const long = new Date(end).getTime() - new Date(start).getTime() >= 24 * 3600_000;
  return `${fmtZoned(start, tz)}–${fmtZoned(end, tz, long)}`;
}

/** «4 ч», «1 ч 30 мин», «45 мин». */
export function fmtMinutes(min: number): string {
  const h = Math.floor(min / 60);
  const m = min % 60;
  if (!h) return `${m} мин`;
  return m ? `${h} ч ${m} мин` : `${h} ч`;
}

/** Длительность окна по началу и концу «22:00» → «02:00» (через полночь — следующий день). */
export function durationBetween(start: string, end: string): number {
  const toMin = (s: string) => {
    const [h, m] = s.split(":").map(Number);
    return h * 60 + m;
  };
  if (!/^\d\d:\d\d$/.test(start) || !/^\d\d:\d\d$/.test(end)) return 0;
  const d = (toMin(end) - toMin(start) + 24 * 60) % (24 * 60);
  return d === 0 ? 24 * 60 : d;
}

export function endTime(start: string, minutes: number): string {
  if (!/^\d\d:\d\d$/.test(start)) return "";
  const [h, m] = start.split(":").map(Number);
  const t = (h * 60 + m + minutes) % (24 * 60);
  return `${String(Math.floor(t / 60)).padStart(2, "0")}:${String(t % 60).padStart(2, "0")}`;
}

/** Окна, в которые можно поставить заявку: включённые рабочие окна с ближайшей датой. */
export function usableWindows(list: WindowOut[] | null | undefined): WindowOut[] {
  return (list ?? []).filter((w) => w.kind !== "blackout" && w.is_active && w.next);
}
