// Даты в интерфейсе — «04.11.2026 16:54» (раздел «Единый стиль»).
const dtf = new Intl.DateTimeFormat("ru-RU", {
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const dtfDay = new Intl.DateTimeFormat("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
const dtfShort = new Intl.DateTimeFormat("ru-RU", { day: "2-digit", month: "2-digit" });
const dtfFull = new Intl.DateTimeFormat("ru-RU", {
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

/** API отдаёт naive UTC без зоны — считаем такие строки UTC. */
export function parseDate(s: string | null | undefined): Date | null {
  if (!s) return null;
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtDate(s: string | null | undefined): string {
  const d = parseDate(s);
  return d ? dtf.format(d) : "—";
}

/** «04.11.2026» — для дат без времени (сроки договора, начало недели). */
export function fmtDay(s: string | null | undefined): string {
  if (!s) return "—";
  const d = /^\d{4}-\d{2}-\d{2}$/.test(s) ? new Date(`${s}T00:00:00`) : parseDate(s);
  return d && !Number.isNaN(d.getTime()) ? dtfDay.format(d) : "—";
}

/** «04.11» — подписи оси по неделям. */
export function fmtDayShort(s: string): string {
  const d = new Date(`${s}T00:00:00`);
  return Number.isNaN(d.getTime()) ? s : dtfShort.format(d);
}

/** «2 дн. назад», «5 мин назад» — для ленты событий. */
export function fmtAgo(s: string | null | undefined, now = Date.now()): string {
  const d = parseDate(s);
  if (!d) return "—";
  const sec = Math.round((now - d.getTime()) / 1000);
  if (sec < 60) return "только что";
  const m = Math.round(sec / 60);
  if (m < 60) return `${m} мин назад`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} ч назад`;
  const days = Math.round(h / 24);
  if (days < 30) return `${days} ${plural(days, ["день", "дня", "дней"])} назад`;
  return fmtDay(s);
}

export function fmtDateFull(s: string | null | undefined): string {
  const d = parseDate(s);
  return d ? dtfFull.format(d) : "—";
}

export function fmtDuration(from: string | null, to: string | null, now = Date.now()): string {
  const a = parseDate(from);
  if (!a) return "—";
  const b = parseDate(to)?.getTime() ?? now;
  let sec = Math.max(0, Math.round((b - a.getTime()) / 1000));
  const h = Math.floor(sec / 3600);
  sec -= h * 3600;
  const m = Math.floor(sec / 60);
  const s = sec - m * 60;
  if (h) return `${h} ч ${m} мин`;
  if (m) return `${m} мин ${s} с`;
  return `${s} с`;
}

export function fmtNumber(n: number): string {
  return n.toLocaleString("ru-RU");
}

export function fmtDelta(n: number): string {
  if (n === 0) return "без изменений";
  return n > 0 ? `+${fmtNumber(n)}` : `−${fmtNumber(Math.abs(n))}`;
}

/** Склонение: plural(5, ["хост", "хоста", "хостов"]). */
export function plural(n: number, forms: [string, string, string]): string {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return forms[2];
  if (b > 1 && b < 5) return forms[1];
  if (b === 1) return forms[0];
  return forms[2];
}

/** Значение для <input type="datetime-local"> в локальном времени браузера. */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Локальное время из формы -> ISO в UTC для API; пустое/битое -> undefined. */
export function localToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** «2 ч 05 мин», «4 мин», «40 с». */
export function fmtEta(sec: number): string {
  if (sec < 60) return `${Math.max(1, Math.round(sec))} с`;
  const m = Math.round(sec / 60);
  if (m < 60) return `${m} мин`;
  return `${Math.floor(m / 60)} ч ${String(m % 60).padStart(2, "0")} мин`;
}


/** Куда вернуться после входа: только свой путь, не внешний адрес. */
export function safeNext(v: string | null): string {
  return v && v.startsWith("/") && !v.startsWith("//") && !v.startsWith("/\\") ? v : "/";
}
