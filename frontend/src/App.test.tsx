import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import { mockApi } from "./test/fetchMock";
import { brief, detail, engineer, manager, me, project, windowOut, windowPlan } from "./test/fixtures";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  setToken(null);
});

describe("вход", () => {
  it("без токена ведёт на вход и возвращает на исходную страницу", async () => {
    const calls = mockApi({
      "POST /auth/token": { access_token: "t1", token_type: "bearer", expires_in: 3600 },
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/tickets": [brief],
      "/projects/p1/ticket-facets": { os: [], kinds: [] },
      "/projects/p1/jobs": [],
    });
    renderAt("/tickets");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Имя пользователя"), "eng");
    await user.type(screen.getByLabelText("Пароль"), "secret-password");
    await user.click(screen.getByRole("button", { name: /Войти/ }));
    expect(await screen.findByRole("heading", { name: "Заявки" })).toBeInTheDocument();
    expect(sessionStorage.getItem("platform.token")).toBe("t1");
    expect(await screen.findByText(brief.title)).toBeInTheDocument();
    expect(calls.some((c) => c.path.startsWith("/projects/p1/tickets?state=open"))).toBe(true);
  });
});

describe("заявки", () => {
  beforeEach(() => setToken("t"));

  it("фильтр из адреса уходит в API, строка открывает шторку с «Взять»", async () => {
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/tickets": [brief],
      "/projects/p1/ticket-facets": { os: [], kinds: [] },
      "/projects/p1/jobs": [],
      "/tickets/5": detail,
      "POST /tickets/5/take": { ...brief, status: "assigned" },
    });
    renderAt("/tickets?severity=high&assignee=none");
    const row = await screen.findByRole("row", { name: /Заявка №5/ });
    expect(calls.find((c) => c.path.startsWith("/projects/p1/tickets"))!.path).toContain("severity=high");
    expect(calls.find((c) => c.path.startsWith("/projects/p1/tickets"))!.path).toContain("assignee=none");
    const user = userEvent.setup();
    await user.click(row);
    const drawer = await screen.findByRole("dialog");
    await user.click(await within(drawer).findByRole("button", { name: /Взять/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/tickets/5/take")).toBe(true));
    // исполнитель не видит массовых действий
    expect(screen.queryByLabelText("Выбрать все на странице")).not.toBeInTheDocument();
  });

  it("руководитель выбирает заявки и переводит их массово", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/tickets": [brief, { ...brief, id: 6, title: "Вторая" }],
      "/projects/p1/ticket-facets": { os: [], kinds: [] },
      "/projects/p1/jobs": [],
      "POST /projects/p1/tickets/bulk": { changed: [5], unchanged: [], failed: [{ id: 6, error: "Переход запрещён" }] },
    });
    renderAt("/tickets");
    const user = userEvent.setup();
    await user.click(await screen.findByLabelText("Выбрать все на странице"));
    await user.click(screen.getByRole("button", { name: /Перевести/ }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Применить" }));
    expect(await screen.findByText(/№6: Переход запрещён/)).toBeInTheDocument();
    const bulk = calls.find((c) => c.path === "/projects/p1/tickets/bulk")!;
    expect(bulk.body).toMatchObject({ ticket_ids: [5, 6], action: "status", status: "in_progress" });
  });
});

describe("заявка", () => {
  beforeEach(() => setToken("t"));
  it("показывает команды и запускает повторную проверку по выбранным хостам", async () => {
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/tickets/5": { ...detail, can: { ...detail.can, take: false, statuses: ["fixed"] }, assignee: { id: 7, username: "eng", display_name: "Смирнов Д. В." } },
      "/tickets/5/history": { history: [], comments: [] },
      "POST /tickets/5/verify": { ticket: brief, verifications: [] },
    });
    renderAt("/tickets/5");
    expect(await screen.findByText("sudo yum update -y glibc")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Копировать/ }).length).toBe(2);
    // Актив хоста из «Сканера»: имя, критичность, группа со ссылкой на фильтр заявок.
    expect(screen.getByText("srv-01")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Серверы приложений" })).toHaveAttribute("href", "/tickets?group=%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D1%8B%20%D0%BF%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B9");
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Исправлено — проверить/ }));
    const dialog = await screen.findByRole("dialog", { name: "Повторная проверка" });
    // подтверждённый хост не предлагается
    expect(within(dialog).queryByText("10.20.3.31")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Запустить проверку" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/tickets/5/verify")).toBe(true));
    expect(calls.find((c) => c.path === "/tickets/5/verify")!.body).toEqual({ hosts: null, mark_fixed: true });
  });
});

describe("права", () => {
  beforeEach(() => setToken("t"));
  it("исполнитель не видит администрирования и получает отказ по прямой ссылке", async () => {
    mockApi({ "/me": engineer, "/projects": [project], "/projects/p1/jobs": [] });
    renderAt("/admin/users");
    expect(await screen.findByText("Нет доступа")).toBeInTheDocument();
    expect(screen.queryByText("Администрирование")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Мои задачи/ })).toBeInTheDocument();
  });
});

describe("окна и план", () => {
  beforeEach(() => setToken("t"));

  it("показывает итог «закроет N», заявку вне окна и снимает заявку с окна", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/windows": [windowOut, { ...windowOut, id: 4, kind: "blackout", name: "Новогодняя заморозка", tickets: 0, next: null }],
      "/projects/p1/calendar": { from: "", to: "", items: [{ ...windowOut.next!, tickets: 2, will_close: 4 }] },
      "/windows/3/plan": windowPlan,
      "POST /tickets/5/window": { ...brief, window: null },
    });
    renderAt("/windows");
    expect(await screen.findByRole("heading", { name: "Окна и план" })).toBeInTheDocument();
    expect(await screen.findByText("закроет уязвимости")).toBeInTheDocument();
    expect(screen.getByText(/Не помещаются в окно: 1 заявка/)).toBeInTheDocument();
    expect(screen.getByText("Новогодняя заморозка")).toBeInTheDocument();
    expect(screen.getByLabelText(/не помещается в окно/)).toBeInTheDocument();
    // Время — по часам окна (Москва), а не браузера.
    expect(screen.getAllByText("вт 10.11 22:00–02:00").length).toBeGreaterThan(0);
    const user = userEvent.setup();
    await user.click(screen.getAllByRole("button", { name: /Снять/ })[0]);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/tickets/5/window")).toBe(true));
    expect(calls.find((c) => c.path === "/tickets/5/window")!.body).toEqual({ window_id: null });
  });

  it("руководитель создаёт повторяющееся окно «вторник 22:00–02:00»", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/windows": [],
      "/projects/p1/calendar": { from: "", to: "", items: [] },
      "POST /projects/p1/windows": windowOut,
      "/windows/3/plan": windowPlan,
    });
    renderAt("/windows");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Новое окно/ }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Название"), "Ночное окно");
    await user.click(within(dialog).getByRole("button", { name: "Создать" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/projects/p1/windows")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/projects/p1/windows")!.body).toMatchObject({
      name: "Ночное окно",
      kind: "recurring",
      timezone: "Europe/Moscow",
      weekdays: [1],
      start_time: "22:00",
      duration_minutes: 240,
      hosts: [],
    });
  });

  it("наблюдатель видит план без кнопок изменения", async () => {
    mockApi({
      "/me": me(["viewer"], ["view"]),
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/windows": [windowOut],
      "/projects/p1/calendar": { from: "", to: "", items: [] },
      "/windows/3/plan": windowPlan,
    });
    renderAt("/windows");
    expect(await screen.findByText("закроет уязвимости")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Новое окно/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Изменить/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Снять/ })).not.toBeInTheDocument();
  });
});

describe("правила назначения и активы", () => {
  beforeEach(() => setToken("t"));

  const facets = {
    total: 20,
    synced_at: "2026-11-04T20:00:00Z",
    groups: [
      { name: "DMZ", assets: 4, open_tickets: 5 },
      { name: "Резерв", assets: 0, open_tickets: 0 },
    ],
    tags: [{ name: "prod", assets: 14 }],
    owners: [{ name: "Отдел веб-сервисов", assets: 6 }],
    criticality: { critical: 3, high: 7, medium: 6, low: 4 },
  };
  const team = {
    id: 1,
    name: "Веб-сервисы",
    members: [
      { id: 2, username: "anna", display_name: "Анна", available: true },
      { id: 3, username: "boris", display_name: "Борис", available: false },
    ],
    rules: 1,
    created_at: "",
  };
  const rule = {
    id: 7,
    project_id: "p1",
    position: 1,
    name: "DMZ — веб-сервисам",
    is_active: true,
    groups: ["DMZ"],
    tags: [],
    owners: [],
    os: [],
    kinds: ["package"],
    host_match: "all",
    assignee: null,
    team: { id: 1, name: "Веб-сервисы", members: 1 },
    created_at: "",
    updated_at: "",
  };

  it("руководитель создаёт правило: группа активов → команда по загрузке", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/rules": [],
      "/teams": [team],
      "/projects/p1/asset-facets": facets,
      "/projects/p1/ticket-facets": { os: [{ id: "Debian 12", total: 5, open: 5 }], kinds: [], groups: [] },
      "/users/assignable": [],
      "POST /projects/p1/rules": rule,
    });
    renderAt("/rules");
    expect(await screen.findByRole("heading", { name: "Правила назначения" })).toBeInTheDocument();
    expect(await screen.findByText("Правил пока нет")).toBeInTheDocument();
    expect(screen.getByText("Борис (не назначается)")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Новое правило/ }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Название"), "DMZ — веб-сервисам");
    await user.click(await within(dialog).findByRole("button", { name: /DMZ/ }));
    await user.click(within(dialog).getByRole("button", { name: "Пакет" }));
    expect(within(dialog).getByRole("radio", { name: "Для всех хостов заявки" })).toHaveAttribute("aria-checked", "true");
    await user.click(within(dialog).getByRole("button", { name: "Создать" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/projects/p1/rules")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/projects/p1/rules")!.body).toEqual({
      name: "DMZ — веб-сервисам",
      is_active: true,
      groups: ["DMZ"],
      tags: [],
      owners: [],
      os: [],
      kinds: ["package"],
      host_match: "all",
      assignee_id: null,
      team_id: 1,
    });
  });

  it("применение правил показывает предпросмотр и назначает после подтверждения", async () => {
    const decision = (id: number, assigned: boolean) => ({
      ticket_id: id,
      title: `Заявка ${id}`,
      severity: "high",
      kind: "package",
      os: "Debian 12",
      rule: assigned ? { id: 7, name: rule.name } : null,
      assignee: assigned ? { id: 2, display_name: "Анна" } : null,
      note: assigned ? "" : "ни одно правило не подошло",
    });
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/rules": [rule],
      "/teams": [team],
      "POST /projects/p1/rules/apply": (_u: URL, init?: RequestInit) => {
        const dry = JSON.parse(String(init!.body)).dry_run;
        return { dry_run: dry, tickets: 2, assigned: 1, items: [decision(11, true), decision(12, false)] };
      },
    });
    renderAt("/rules");
    expect(await screen.findByText(rule.name)).toBeInTheDocument();
    expect(screen.getByText("по загрузке, 1 участник")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Применить к новым заявкам/ }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("ни одно правило не подошло")).toBeInTheDocument();
    expect(within(dialog).getByText("Анна")).toBeInTheDocument();
    expect(calls.filter((c) => c.path === "/projects/p1/rules/apply").map((c) => c.body)).toEqual([{ dry_run: true }]);
    await user.click(within(dialog).getByRole("button", { name: "Назначить 1" }));
    expect(await within(dialog).findByText(/Назначено 1 из 2/)).toBeInTheDocument();
    expect(calls.filter((c) => c.path === "/projects/p1/rules/apply").map((c) => c.body)).toEqual([{ dry_run: true }, { dry_run: false }]);
  });

  it("исполнитель не видит пункта «Правила назначения», активы фильтруются по группе", async () => {
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/asset-facets": facets,
      "/projects/p1/assets": [
        {
          id: 1,
          address: "10.20.1.11",
          hostname: "web-01",
          owner: "Отдел веб-сервисов",
          criticality: "high",
          tags: ["prod"],
          groups: ["DMZ"],
          os_family: "debian",
          os_guess: "Debian 12",
          engagement_id: 7,
          scanner_asset_id: 501,
          open_tickets: 3,
          synced_at: "",
        },
      ],
      "POST /projects/p1/assets/sync": { assets: 20, created: 0, updated: 20, removed: 1, groups: 6, groups_removed: 0, errors: [] },
    });
    renderAt("/assets");
    expect(await screen.findByRole("heading", { name: "Активы" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Правила назначения/ })).not.toBeInTheDocument();
    expect(await screen.findByText("web-01 · Debian 12")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "3" })).toHaveAttribute("href", "/tickets?host=10.20.1.11");
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("group", { name: "Фильтр по группе" })).getByRole("button", { name: /DMZ/ }));
    await waitFor(() => expect(calls.some((c) => c.path.startsWith("/projects/p1/assets?group=DMZ"))).toBe(true));
    await user.click(screen.getByRole("button", { name: /Обновить из «Сканера»/ }));
    expect(await screen.findByText(/Обновлено из «Сканера»: 20 активов, удалено 1/)).toBeInTheDocument();
  });

  it("в заявках есть фильтр по группе активов", async () => {
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/tickets": [brief],
      "/projects/p1/ticket-facets": { os: [], kinds: [], groups: [{ id: "DMZ", total: 3, open: 2 }] },
    });
    renderAt("/tickets?group=DMZ");
    expect(await screen.findByRole("combobox", { name: "Группа активов" })).toHaveValue("DMZ");
    await waitFor(() => expect(calls.some((c) => c.path.includes("group=DMZ"))).toBe(true));
  });
});

describe("доступ к хостам", () => {
  beforeEach(() => setToken("t"));

  const cred = {
    id: 3,
    project_id: "p1",
    name: "Linux-серверы (deploy)",
    username: "deploy",
    auth: "password",
    port: 22,
    become: "sudo",
    key_type: "",
    key_fingerprint: "",
    has_secret: true,
    has_become_password: false,
    hosts: ["10.20.1.0/24"],
    groups: [],
    is_active: true,
    note: "",
    last_check: null,
    created_at: "",
    updated_at: "",
  };
  const pinned = {
    id: 21,
    host: "10.20.1.11",
    port: 22,
    key_type: "ssh-ed25519",
    fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    status: "pinned",
    pinned_via: "tofu",
    pinned_by: null,
    pinned_at: "2026-11-05T10:00:00Z",
    last_seen_at: "2026-11-05T10:00:00Z",
    mismatch: null,
  };
  const changed = {
    ...pinned,
    id: 22,
    host: "10.20.1.13",
    status: "mismatch",
    mismatch: { key_type: "ssh-ed25519", fingerprint: "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", at: "2026-11-05T11:00:00Z", count: 1 },
  };
  const via = { id: 3, name: cred.name, username: "deploy", port: 22, why: "subnet", detail: "10.20.1.0/24" };
  const hosts = [
    { host: "10.20.1.11", hostname: "web-01", groups: ["DMZ"], in_project: true, credential: via, keys: [pinned] },
    { host: "10.20.1.13", hostname: "web-03", groups: ["DMZ"], in_project: true, credential: via, keys: [changed] },
    { host: "10.20.2.21", hostname: "arm-01", groups: [], in_project: true, credential: null, keys: [] },
  ];

  it("руководитель заводит учётку: секреты уходят только в запросе создания", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/ssh-credentials": [],
      "/projects/p1/ssh-hosts": [],
      "/projects/p1/asset-facets": { groups: [{ name: "DMZ", assets: 4 }], tags: [], owners: [], criticality: [] },
      "POST /projects/p1/ssh-credentials": cred,
    });
    renderAt("/access");
    expect(await screen.findByRole("heading", { name: "Доступ к хостам" })).toBeInTheDocument();
    expect(await screen.findByText("Учёток пока нет")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Новая учётка/ }));
    const dialog = await screen.findByRole("dialog");
    const create = within(dialog).getByRole("button", { name: "Создать" });
    await user.type(within(dialog).getByLabelText("Название"), "Linux-серверы (deploy)");
    await user.type(within(dialog).getByLabelText("Логин на хосте"), "deploy");
    expect(create).toBeDisabled(); // без пароля нельзя
    await user.type(within(dialog).getByLabelText("Пароль", { selector: "input[type=password]" }), "S3cret-pass");
    await user.type(within(dialog).getByLabelText(/Адреса и подсети/), "10.20.1.0/24");
    await user.click(await within(dialog).findByRole("button", { name: /DMZ/ }));
    await user.click(create);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/projects/p1/ssh-credentials")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({
      name: "Linux-серверы (deploy)",
      username: "deploy",
      auth: "password",
      port: 22,
      become: "sudo",
      hosts: ["10.20.1.0/24"],
      groups: ["DMZ"],
      is_active: true,
      note: "",
      password: "S3cret-pass",
    });
  });

  it("показывает изменившийся ключ и принимает новый ключ с причиной", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/ssh-credentials": [cred],
      "/projects/p1/ssh-hosts": hosts,
      "POST /host-keys/22/accept": { ...changed, status: "pinned", mismatch: null },
    });
    renderAt("/access");
    expect(await screen.findByText(/У 1 хоста изменился ключ SSH/)).toBeInTheDocument();
    expect(screen.getByText("ключ изменился")).toBeInTheDocument();
    expect(screen.getByText("нет подходящей")).toBeInTheDocument();
    expect(screen.getAllByText("подсеть «10.20.1.0/24»", { exact: false })).toHaveLength(2);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Без учётки/ }));
    expect(screen.queryByText("web-01", { exact: false })).not.toBeInTheDocument();
    expect(screen.getByText("arm-01")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Все/ }));
    await user.click(screen.getByRole("button", { name: "Принять новый" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(changed.mismatch.fingerprint)).toBeInTheDocument();
    const accept = within(dialog).getByRole("button", { name: "Принять ключ" });
    expect(accept).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Причина/), "Хост переустановлен");
    await user.click(accept);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/host-keys/22/accept")).toBe(true));
    expect(calls.find((c) => c.path === "/host-keys/22/accept")!.body).toEqual({ reason: "Хост переустановлен" });
  });

  it("проверка входа показывает итог и закреплённый ключ", async () => {
    mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/ssh-credentials": [cred],
      "/projects/p1/ssh-hosts": hosts,
      "POST /ssh-credentials/3/check": {
        result: "ok",
        label: "Вход выполнен",
        message: "Вход выполнен",
        ok: true,
        facts: { user: "deploy", uid: 1000, os: "Debian GNU/Linux 12 (bookworm)", become: "sudo" },
        key_state: "new",
        host_key: pinned,
      },
    });
    renderAt("/access");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Проверить/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText(/Хост проекта/)).toHaveValue("10.20.1.11");
    await user.click(within(dialog).getByRole("button", { name: /Проверить/ }));
    expect(await within(dialog).findByText(/deploy \(uid 1000\) · Debian GNU\/Linux 12 \(bookworm\) · sudo работает/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Ключ хоста закреплён/)).toBeInTheDocument();
  });

  it("исполнитель не видит пункта «Доступ к хостам»", async () => {
    mockApi({ "/me": engineer, "/projects": [project], "/projects/p1/jobs": [], "/projects/p1/tickets": [brief], "/projects/p1/ticket-facets": { os: [], kinds: [] } });
    renderAt("/tickets");
    expect(await screen.findByRole("heading", { name: "Заявки" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Доступ к хостам/ })).not.toBeInTheDocument();
  });
});
