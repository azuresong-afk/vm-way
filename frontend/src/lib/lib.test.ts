import { fmtDate, fmtDay, plural, safeNext } from "./format";
import { reasonRequired } from "./labels";
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
