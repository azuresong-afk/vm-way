import { durationBetween, endTime, fmtRange, fmtZoned, isoToZoned, zonedToIso } from "./zoned";

describe("время окна в его часовом поясе", () => {
  it("переводит часы заказчика в UTC и обратно", () => {
    expect(zonedToIso("2026-11-10T22:00", "Europe/Moscow")).toBe("2026-11-10T19:00:00.000Z");
    expect(zonedToIso("2026-11-10T01:30", "Asia/Yekaterinburg")).toBe("2026-11-09T20:30:00.000Z");
    expect(isoToZoned("2026-11-10T19:00:00Z", "Europe/Moscow")).toBe("2026-11-10T22:00");
    expect(zonedToIso("10.11.2026", "Europe/Moscow")).toBeNull();
  });
  it("переход на летнее время учитывается", () => {
    expect(zonedToIso("2026-07-01T12:00", "Europe/Berlin")).toBe("2026-07-01T10:00:00.000Z");
    expect(zonedToIso("2026-01-01T12:00", "Europe/Berlin")).toBe("2026-01-01T11:00:00.000Z");
  });
  it("подписи: день недели, интервал через полночь", () => {
    expect(fmtZoned("2026-11-10T19:00:00Z", "Europe/Moscow")).toBe("вт 10.11 22:00");
    expect(fmtRange("2026-11-10T19:00:00Z", "2026-11-10T23:00:00Z", "Europe/Moscow")).toBe("вт 10.11 22:00–02:00");
    expect(fmtRange("2026-12-28T00:00:00Z", "2027-01-09T00:00:00Z", "UTC")).toBe("пн 28.12 00:00–сб 09.01 00:00");
  });
  it("длительность по началу и концу", () => {
    expect(durationBetween("22:00", "02:00")).toBe(240);
    expect(durationBetween("09:00", "09:00")).toBe(24 * 60);
    expect(endTime("22:00", 240)).toBe("02:00");
  });
});
