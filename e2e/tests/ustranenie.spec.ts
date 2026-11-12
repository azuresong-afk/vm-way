import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "@playwright/test";

// Сквозной сценарий на демо-стенде: вход → импорт → заявка → раскатка → повторная проверка.
// Шаги зависят друг от друга и меняют данные стенда, поэтому идут по порядку (serial)
// и рассчитаны на чистый стенд. Демо-данные: проект «Северный порт», мок «Сканера»,
// пользователи manager (Руководитель) и engineer (Исполнитель с правом запуска раскаток).

/** Пароль демо-пользователей: E2E_DEMO_PASSWORD или VM_DEMO_PASSWORD из .env в корне. */
function demoPassword(): string {
  if (process.env.E2E_DEMO_PASSWORD) return process.env.E2E_DEMO_PASSWORD;
  try {
    const env = readFileSync(resolve(__dirname, "../../.env"), "utf8");
    const m = env.match(/^VM_DEMO_PASSWORD=(.+)$/m);
    if (m) return m[1].trim();
  } catch {
    // .env нет — ниже понятная ошибка
  }
  throw new Error("Нет пароля демо-пользователей: задайте E2E_DEMO_PASSWORD или VM_DEMO_PASSWORD в .env (scripts/gen-env.sh --demo)");
}

const PASSWORD = demoPassword();
const GLIBC = "Обновить glibc на РЕД ОС 7.3";
const OPENSSH = "Обновить openssh-server на Debian 12";

const menu = (page: Page) => page.getByRole("navigation", { name: "Основное меню" });
const loginForm = (page: Page) => page.getByRole("form", { name: "Вход в систему" });
/** Статус в шапке карточки (заявки или раскатки) — первая метка под заголовком. */
const headStatus = (page: Page) => page.locator(".page-head .pill").first();

async function login(page: Page, username: string) {
  await page.goto("/");
  await loginForm(page).getByLabel("Имя пользователя").fill(username);
  await loginForm(page).getByLabel("Пароль").fill(PASSWORD);
  await loginForm(page).getByRole("button", { name: "Войти" }).click();
  await expect(menu(page)).toBeVisible();
}

async function logout(page: Page) {
  await menu(page).getByRole("button", { name: "Выйти" }).click();
  await expect(loginForm(page)).toBeVisible();
}

/** «Заявки» со всеми статусами; возвращает общее число заявок из строки «Показано … из N». */
async function totalTickets(page: Page): Promise<number> {
  await menu(page).getByRole("link", { name: "Заявки", exact: true }).click();
  await page.getByRole("combobox", { name: "Статус" }).selectOption({ label: "Все статусы" });
  const shown = page.getByText(/Показано \d+–\d+ из \d+/);
  await expect(shown).toBeVisible();
  return Number((await shown.innerText()).match(/из (\d+)/)![1]);
}

/** Открыть карточку заявки из списка: строка → боковая панель → «Открыть заявку». */
async function openTicket(page: Page, title: string) {
  await menu(page).getByRole("link", { name: "Заявки", exact: true }).click();
  await page.getByRole("row", { name: new RegExp(title) }).click();
  await page.getByRole("dialog").getByRole("link", { name: "Открыть заявку" }).click();
  await expect(page.getByRole("heading", { level: 1, name: new RegExp(title) })).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test.describe("Демо-стенд: от входа до подтверждённого исправления", () => {
  // Адрес раскатки передаётся между шагами: готовит исполнитель, утверждает руководитель.
  let rolloutUrl = "";

  test("вход: руководитель видит сводку демо-проекта и может выйти", async ({ page }) => {
    await page.goto("/");
    await expect(loginForm(page)).toBeVisible();
    await expect(loginForm(page).getByRole("button", { name: "Войти" })).toBeDisabled();

    await login(page, "manager");
    await expect(menu(page)).toContainText("Руководитель");
    await expect(page.getByRole("heading", { level: 1, name: "Сводка" })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Проект" })).toContainText("Северный порт");
    for (const item of ["Заявки", "Мои задачи", "Раскатки", "Журнал аудита"]) {
      await expect(menu(page).getByRole("link", { name: item, exact: true })).toBeVisible();
    }

    await logout(page);
  });

  test("импорт: повторный импорт прогонов не плодит дубли", async ({ page }) => {
    await login(page, "manager");
    // Три плановых прогона демо-«Сканера» импортированы при старте стенда.
    await expect(page.getByText(/Последний прогон «Сканера»: №\d+/)).toBeVisible();
    const before = await totalTickets(page);
    expect(before).toBeGreaterThan(0);

    await menu(page).getByRole("link", { name: "Сводка", exact: true }).click();
    const hero = page.getByRole("heading", { level: 2, name: /открытые уязвимости в \d+ заявк/ });
    const heroBefore = await hero.innerText();
    await page.getByRole("button", { name: "Импортировать новые прогоны" }).click();
    await expect(page.getByText("Импорт завершён, сводка обновлена")).toBeVisible({ timeout: 60_000 });
    await expect(hero).toHaveText(heroBefore);

    expect(await totalTickets(page)).toBe(before);
  });

  test("заявка: исполнитель находит её по CVE, берёт в работу и комментирует", async ({ page }) => {
    await login(page, "engineer");
    await menu(page).getByRole("link", { name: "Заявки", exact: true }).click();

    // Поиск по CVE сужает список до заявок с openssh и сохраняется в адресе страницы.
    await page.getByRole("searchbox", { name: "Поиск заявок" }).fill("CVE-2024-6387");
    await expect(page).toHaveURL(/q=CVE-2024-6387/);
    const rows = page.getByRole("row", { name: /^Заявка №/ });
    await expect(page.getByRole("row", { name: new RegExp(OPENSSH) })).toBeVisible();
    await expect(page.getByRole("row", { name: /glibc/ })).toHaveCount(0);
    for (const row of await rows.all()) await expect(row).toContainText("CVE-2024-6387");

    await page.getByRole("row", { name: new RegExp(OPENSSH) }).click();
    await page.getByRole("dialog").getByRole("link", { name: "Открыть заявку" }).click();
    await expect(page.getByRole("heading", { level: 1, name: new RegExp(OPENSSH) })).toBeVisible();
    await expect(headStatus(page)).toHaveText("Новая");

    // Карточка: что сделать (команда из плана «Сканера») и хосты заявки.
    const todo = page.getByRole("region", { name: "Что сделать" });
    await expect(todo).toContainText("apt-get install --only-upgrade -y openssh-server");
    const hosts = page.getByRole("region", { name: "Хосты" });
    await expect(hosts).toContainText("0 из 8");
    await expect(hosts.getByRole("row", { name: /10\.20\.1\.11/ })).toContainText("Открыт");

    await page.getByRole("button", { name: "Взять", exact: true }).click();
    await expect(headStatus(page)).toHaveText("Назначена");
    const info = page.getByRole("region", { name: "Сведения" });
    await expect(info).toContainText("Смирнов Д. В.");

    const history = page.getByRole("region", { name: "История и комментарии" });
    const comment = `Сквозной тест: обновление запланировано (${Date.now()})`;
    await history.getByRole("textbox", { name: "Комментарий" }).fill(comment);
    await history.getByRole("button", { name: "Отправить" }).click();
    await expect(history.getByRole("listitem").filter({ hasText: comment })).toBeVisible();
    await expect(history).toContainText("Заявка взята в работу");

    // Взятая заявка появляется в «Моих задачах».
    await menu(page).getByRole("link", { name: "Мои задачи", exact: true }).click();
    await expect(page.getByRole("row", { name: new RegExp(OPENSSH) })).toBeVisible();
  });

  test("раскатка: исполнитель готовит и делает пробный прогон", async ({ page }) => {
    await login(page, "engineer");
    await openTicket(page, GLIBC);
    await page.getByRole("button", { name: "Взять", exact: true }).click();
    await expect(headStatus(page)).toHaveText("Назначена");

    await page.getByRole("button", { name: "Подготовить раскатку" }).click();
    const form = page.getByRole("dialog", { name: /Раскатка по заявке №\d+/ });
    // Форма заполнена из заявки: пакет, исправленная версия и неподтверждённые хосты.
    await expect(form.getByRole("textbox", { name: /^Пакеты/ })).toHaveValue("glibc");
    await expect(form.getByRole("textbox", { name: /^Исправленная версия/ })).toHaveValue("2.35-9.el7");
    await expect(form.getByRole("group", { name: "Хосты (3 из 3)" })).toBeVisible();

    // Недопустимое имя пакета не даёт подготовить раскатку.
    await form.getByRole("textbox", { name: /^Пакеты/ }).fill("glibc;reboot");
    await expect(form.getByRole("button", { name: "Подготовить" })).toBeDisabled();
    await form.getByRole("textbox", { name: /^Пакеты/ }).fill("glibc");
    await form.getByRole("button", { name: "Подготовить" }).click();

    await expect(page).toHaveURL(/\/rollouts\/\d+$/);
    rolloutUrl = new URL(page.url()).pathname;
    await expect(headStatus(page)).toHaveText("Черновик");

    await page.getByRole("button", { name: "Пробный прогон", exact: true }).click();
    await expect(headStatus(page)).toHaveText("Ждёт утверждения", { timeout: 60_000 });
    const hosts = page.getByRole("region", { name: "Хосты" });
    await expect(hosts.getByRole("row", { name: /Пробный прогон пройден/ })).toHaveCount(3);
    await expect(hosts).toContainText("glibc → 2.35-9.el7");
    // Четыре глаза: тот, кто готовил, утвердить не может.
    await expect(page.getByRole("button", { name: "Утвердить" })).toHaveCount(0);
  });

  test("раскатка: руководитель утверждает, но не запускает", async ({ page }) => {
    expect(rolloutUrl, "раскатка подготовлена предыдущим шагом").not.toBe("");
    await login(page, "manager");
    await menu(page).getByRole("link", { name: "Раскатки", exact: true }).click();
    await page.getByRole("link", { name: /Обновить glibc — заявка №\d+/ }).click();
    await expect(page).toHaveURL(new RegExp(`${rolloutUrl}$`));

    await page.getByRole("button", { name: "Утвердить" }).click();
    const dialog = page.getByRole("dialog", { name: /Утвердить раскатку №\d+/ });
    // У раскатки нет окна обслуживания — запуск вне окна требует причины.
    await expect(dialog.getByRole("button", { name: "Утвердить" })).toBeDisabled();
    await dialog.getByRole("textbox", { name: "Причина запуска вне окна" }).fill("Сквозной тест: срочное исправление");
    await dialog.getByRole("button", { name: "Утвердить" }).click();

    await expect(headStatus(page)).toHaveText("Утверждена");
    await expect(page.getByRole("button", { name: "Запустить" })).toHaveCount(0);
  });

  test("раскатка: исполнитель запускает, повторная проверка закрывает заявку", async ({ page }) => {
    expect(rolloutUrl, "раскатка подготовлена и утверждена предыдущими шагами").not.toBe("");
    await login(page, "engineer");
    await page.goto(rolloutUrl);
    await expect(headStatus(page)).toHaveText("Утверждена");

    await page.getByRole("button", { name: "Запустить" }).click();
    await expect(headStatus(page)).toHaveText("Завершена", { timeout: 90_000 });
    const hosts = page.getByRole("region", { name: "Хосты" });
    await expect(hosts.getByRole("row", { name: /Изменение выполнено/ })).toHaveCount(3);
    await expect(hosts.getByRole("row", { name: /10\.20\.3\.32/ })).toContainText("2.35-6.el7 → 2.35-9.el7");

    // После раскатки «Сканер» сам перепроверяет хосты; страница раскатки следит за проверкой
    // и показывает её итог в «Параметрах».
    const params = page.getByRole("region", { name: "Параметры" });
    await expect(params.getByRole("heading", { name: "Повторная проверка" })).toBeVisible();
    await expect(params.getByText(/Прогон №\d+ «Сканера»/).locator("xpath=ancestor::*[contains(@class,'list-row')]")).toContainText("Подтверждено", {
      timeout: 90_000,
    });

    await params.getByRole("link", { name: new RegExp(GLIBC) }).click();
    await expect(page.getByRole("heading", { level: 1, name: new RegExp(GLIBC) })).toBeVisible();
    await expect(headStatus(page)).toHaveText("Подтверждено");
    await expect(page.getByRole("region", { name: "Хосты" })).toContainText("4 из 4");
    await expect(page.getByRole("region", { name: "Повторные проверки" })).toContainText("подтверждено 3, не подтверждено 0, не проверено 0");
    await expect(page.getByRole("region", { name: "История и комментарии" })).toContainText(/Раскатка №\d+ завершена/);
  });

  test("повторная проверка: исправленное закрыто, неисправленное осталось, недоступное помечено", async ({ page }) => {
    await login(page, "engineer");
    await menu(page).getByRole("link", { name: "Мои задачи", exact: true }).click();
    await page.getByRole("row", { name: new RegExp(OPENSSH) }).click();
    await page.getByRole("dialog").getByRole("link", { name: "Открыть заявку" }).click();
    await expect(page.getByRole("heading", { level: 1, name: new RegExp(OPENSSH) })).toBeVisible();

    await page.getByRole("button", { name: "Исправлено — проверить" }).click();
    const dialog = page.getByRole("dialog", { name: "Повторная проверка" });
    await expect(dialog.getByRole("group", { name: "Хосты (8 из 8)" })).toBeVisible();
    await expect(dialog.getByRole("checkbox", { name: /Перевести в «Исправлено, ждёт проверки»/ })).toBeChecked();
    await dialog.getByRole("button", { name: "Запустить проверку" }).click();

    await expect(headStatus(page)).toHaveText("Исправлено, ждёт проверки");
    // Фоновая задача видна в плашке шапки; когда плашка исчезла — проверка закончилась.
    const chip = page.getByRole("banner").getByRole("status");
    await expect(chip).toBeVisible();
    await expect(chip).toHaveCount(0, { timeout: 90_000 });
    // Карточка заявки сама не обновляется по окончании проверки — перечитываем страницу.
    await page.reload();

    // В «мире» демо-«Сканера» openssh обновлён на 10.20.1.11–15, на .16 и .17 — нет, .18 не отвечает.
    await expect(headStatus(page)).toHaveText("Не подтверждено");
    const hosts = page.getByRole("region", { name: "Хосты" });
    await expect(hosts).toContainText("5 из 8");
    for (const ip of ["10.20.1.11", "10.20.1.15"]) {
      await expect(hosts.getByRole("row", { name: new RegExp(ip.replaceAll(".", "\\.")) })).toContainText("Подтверждено");
    }
    await expect(hosts.getByRole("row", { name: /10\.20\.1\.16/ })).toContainText("уязвимость осталась: CVE-2024-6387");
    await expect(hosts.getByRole("row", { name: /10\.20\.1\.18/ })).toContainText("хост недоступен");
    await expect(page.getByRole("region", { name: "Повторные проверки" })).toContainText("подтверждено 5, не подтверждено 2, не проверено 1");
  });
});
