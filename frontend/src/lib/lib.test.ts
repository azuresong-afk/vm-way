import { fmtDate, fmtDay, plural, safeNext } from "./format";
import { reasonRequired } from "./labels";
import { isoDay, presetRange } from "./reportPeriod";
import { savedTheme } from "../theme/ThemeContext";

describe("формат", () => {
  it("даты как в «Сканере»: 04.11.2026 16:54", () => {
    expect(fmtDate("2026-11-04T13:54:00Z")).toMatch(/^04\.11\.2026,? \d\d:54$/);
    expect(fmtDay("2026-11-04")).toBe("04.11.2026");
    expect(fmtDate(null)).toBe("—");
  });
  it("склонения", () => {
    expect(plural(1, ["заявка", "заявки", "заявок"])).toBe("заявка");
    expect(plural(3, ["заявка", "заявки", "заявок"])).toBe("заявки");
    expect(plural(11, ["заявка", "заявки", "заявок"])).toBe("заявок");
  });
  it("после входа — только на свой путь", () => {
    expect(safeNext("/tickets/5?project=p1")).toBe("/tickets/5?project=p1");
    expect(safeNext("//evil.example")).toBe("/");
    expect(safeNext("https://evil.example")).toBe("/");
    expect(safeNext(null)).toBe("/");
  });
});

describe("правила переходов", () => {
  it("причина нужна для возврата из «Исправлено»; исключения — отдельной формой", () => {
    expect(reasonRequired("fixed")).toBe(true);
    expect(reasonRequired("assigned")).toBe(false);
  });
});

describe("тема", () => {
  beforeEach(() => localStorage.clear());
  it("по умолчанию тёмная, читает и ключ «Сканера»", () => {
    expect(savedTheme()).toBe("dark");
    localStorage.setItem("scanner.theme", "light");
    expect(savedTheme()).toBe("light");
    localStorage.setItem("platform.theme", "dark");
    expect(savedTheme()).toBe("dark");
  });
});

describe("период отчёта", () => {
  const p = { ...{ id: "p1", name: "Демо", client: "", contract_ref: "", status: "active" as const, platform_project_id: null, created_at: "" } };
  it("пресеты считаются от сегодняшнего дня включительно", () => {
    const proj = { ...p, period_from: null, period_to: null };
    expect(presetRange("month", "2026-11-06", proj)).toEqual({ from: "2026-10-08", to: "2026-11-06" });
    expect(presetRange("3m", "2026-11-06", proj)).toEqual({ from: "2026-08-08", to: "2026-11-06" });
    expect(presetRange("year", "2026-03-01", proj)).toEqual({ from: "2025-03-02", to: "2026-03-01" });
  });
  it("срок договора — даты проекта, но не позже сегодня", () => {
    expect(presetRange("contract", "2026-11-06", { ...p, period_from: "2026-09-01", period_to: "2026-12-31" })).toEqual({
      from: "2026-09-01",
      to: "2026-11-06",
    });
    expect(presetRange("contract", "2026-11-06", { ...p, period_from: "2026-01-01", period_to: "2026-06-30" })).toEqual({
      from: "2026-01-01",
      to: "2026-06-30",
    });
    expect(isoDay(new Date(2026, 0, 5))).toBe("2026-01-05");
  });
});
