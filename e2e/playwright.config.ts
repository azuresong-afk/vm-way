import { defineConfig, devices } from "@playwright/test";

// Сквозной тест идёт по поднятому демо-стенду (scripts/gen-env.sh --demo && docker compose up).
// Сценарий меняет данные стенда, поэтому шаги идут строго по порядку в один поток,
// а стенд должен быть чистым (docker compose down -v перед повторным запуском).
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:18081",
    locale: "ru-RU",
    timezoneId: "Europe/Moscow",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
