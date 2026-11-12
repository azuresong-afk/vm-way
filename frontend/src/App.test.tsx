import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import type { ExceptionOut } from "./api/types";
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

  it("идущую проверку можно отменить, отменённая показана с причиной", async () => {
    const check = {
      id: 9, ticket_id: 5, project_id: "p1", source_id: 1, engagement_id: 7, scanner_run_id: 1003, run_id: null,
      targets: ["10.20.3.32"], denied_targets: [], modules: ["vuln"], result: { job_id: 4 }, error: "", requested_by: null,
      created_at: "2026-11-12T08:00:00Z", finished_at: null,
    };
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/tickets/5": {
        ...detail,
        can: { ...detail.can, take: false, verify: false },
        verifications: [
          { ...check, status: "running", can_cancel: true },
          { ...check, id: 8, scanner_run_id: 1002, status: "cancelled", can_cancel: false, result: { cancel_reason: "Хост выведен из работы" } },
        ],
      },
      "/tickets/5/history": { history: [], comments: [] },
      "POST /verifications/9/cancel": { ...check, status: "cancelled", can_cancel: false },
    });
    renderAt("/tickets/5");
    expect(await screen.findByText("Причина: Хост выведен из работы")).toBeInTheDocument();
    expect(screen.getByText("Отменена")).toBeInTheDocument();
    const user = userEvent.setup();
    // Кнопка одна: у отменённой проверки её нет.
    await user.click(screen.getByRole("button", { name: "Отменить" }));
    const dialog = await screen.findByRole("dialog", { name: "Отменить повторную проверку?" });
    expect(within(dialog).getByText(/Прогон №1003 «Сканера» будет остановлен/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Отменить проверку" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/verifications/9/cancel")).toBe(true));
    expect(calls.find((c) => c.path === "/verifications/9/cancel")!.body).toEqual({ reason: "" });
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

describe("раскатки", () => {
  beforeEach(() => setToken("t"));

  const host = {
    id: 1,
    host: "10.20.3.32",
    stage: null,
    status: "dry_ok",
    status_label: "Пробный прогон пройден",
    reason: "",
    credential: { id: 3, name: "deploy" },
    dry_status: "ok",
    dry_plan: [{ package: "glibc", from: "", to: "2.35-9.el7" }],
    dry_note: "",
    versions_before: { glibc: "2.35-6.el7" },
    versions_after: {},
    rollback: [],
    reboot_required: false,
    rebooted: false,
    kernel_before: "",
    kernel_after: "",
    started_at: null,
    finished_at: null,
    duration_ms: 1200,
    canary: true,
  };
  const ro = {
    id: 5,
    project_id: "p1",
    ticket: { id: 42, title: "Обновить glibc на РЕД ОС 7.3 до 2.35-9.el7", status: "in_progress", os: "РЕД ОС 7.3" },
    title: "Обновить glibc — заявка №42",
    template: "package",
    template_label: "Обновление пакетов",
    manager: "dnf",
    packages: ["glibc"],
    fixed_version: "2.35-9.el7",
    service: "",
    command: "",
    window: null,
    canary_host: "10.20.3.32",
    batch_percent: 10,
    failure_threshold: 10,
    status: "pending_approval",
    status_label: "Ждёт утверждения",
    error: "",
    note: "",
    prepared_by: { id: 2, username: "engineer", display_name: "Смирнов Д. В." },
    dry_run_at: "2026-11-05T10:00:00Z",
    dry_run_by: { id: 2, username: "engineer", display_name: "Смирнов Д. В." },
    decided_by: null,
    decided_at: null,
    decision_note: "",
    allow_reboot: false,
    outside_window: false,
    outside_window_reason: "",
    custom_approved: false,
    started_by: null,
    started_at: null,
    finished_at: null,
    stop_requested: false,
    stopped_by: null,
    stop_reason: "",
    verification_ids: [],
    counts: { dry_ok: 1 },
    hosts_total: 1,
    created_at: "2026-11-05T09:00:00Z",
    updated_at: "2026-11-05T10:00:00Z",
    can: { dry_run: false, approve: true, reject: true, start: false, stop: false, cancel: true },
    hosts: [host],
    stages: [
      { key: "dry_run", label: "Пробный прогон", state: "done" },
      { key: "approval", label: "Утверждение", state: "running" },
      { key: "canary", label: "Канарейка", state: "pending", hosts: ["10.20.3.32"] },
      { key: "batches", label: "Партии", state: "pending", batches: [] },
      { key: "verify", label: "Проверка", state: "pending" },
    ],
    step_counts: { "1": 3 },
    verifications: [],
  };

  it("руководитель утверждает: без окна — только вне окна с причиной, перезагрузка — отдельной галочкой", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/rollouts/5": ro,
      "POST /rollouts/5/approve": { ...ro, status: "approved", status_label: "Утверждена", can: { ...ro.can, approve: false } },
    });
    renderAt("/rollouts/5");
    expect(await screen.findByRole("heading", { name: "Обновить glibc — заявка №42" })).toBeInTheDocument();
    expect(screen.getByText("Пробный прогон пройден")).toBeInTheDocument();
    expect(screen.getByText("2.35-9.el7")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Утвердить/ }));
    const dialog = await screen.findByRole("dialog", { name: "Утвердить раскатку №5" });
    const submit = within(dialog).getByRole("button", { name: /Утвердить/ });
    expect(within(dialog).getByRole("checkbox", { name: /вне окна/ })).toBeChecked();
    expect(submit).toBeDisabled(); // нужна причина
    await userEvent.type(within(dialog).getByRole("textbox", { name: "Причина запуска вне окна" }), "срочно, согласовано");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /Разрешить перезагрузку/ }));
    await userEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/rollouts/5/approve")).toBe(true));
    const body = calls.find((c) => c.path === "/rollouts/5/approve")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ allow_reboot: true, outside_window: true, outside_window_reason: "срочно, согласовано" });
    expect(await screen.findByText("Утверждена")).toBeInTheDocument();
  });

  it("журнал хоста: команды с кодом возврата и выводом", async () => {
    mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/rollouts/5": { ...ro, can: { ...ro.can, approve: false, reject: false } },
      "/rollouts/5/steps": [
        { id: 1, host_id: 1, phase: "dry_run", label: "Пробный прогон", command: "sudo -S -p '' dnf upgrade --assumeno glibc", returncode: 1, ok: true, stdout: "Operation aborted.", stderr: "", duration_ms: 900, at: "" },
        { id: 2, host_id: 1, phase: "dry_run", label: "Проверка", command: "sudo -n true", returncode: 1, ok: false, stdout: "", stderr: "sudo: a password is required", duration_ms: 10, at: "" },
      ],
    });
    renderAt("/rollouts/5");
    expect(await screen.findByText(/Ждёт утверждения руководителем/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Журнал 10.20.3.32" }));
    expect(await screen.findByText("sudo -S -p '' dnf upgrade --assumeno glibc")).toBeInTheDocument();
    expect(screen.getByText("sudo: a password is required")).toBeVisible();
  });

  it("исполнитель готовит раскатку из заявки: недопустимое имя пакета не отправляется", async () => {
    const calls = mockApi({
      "/me": { ...engineer, permissions: [...engineer.permissions, "remediate_execute"] },
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/tickets/5": { ...detail, can: { ...detail.can, rollout: true } },
      "/tickets/5/history": { history: [], comments: [] },
      "/rollout-meta": {
        templates: [
          { id: "package", label: "Обновление пакетов" },
          { id: "kernel", label: "Обновление ядра" },
          { id: "service", label: "Перезапуск службы" },
          { id: "custom", label: "Произвольная команда" },
        ],
        managers: [{ id: "dnf", label: "dnf — РЕД ОС, RHEL 8+" }],
        statuses: [],
        host_statuses: [],
        name_pattern: "",
      },
      "/tickets/5/rollout-draft": {
        template: "package",
        manager: "dnf",
        packages: ["glibc"],
        fixed_version: "2.35-9.el7",
        service: "",
        hosts: ["10.20.3.32"],
        canary_host: "10.20.3.32",
        window_id: null,
        batch_percent: 10,
        failure_threshold: 10,
        reboot: false,
        windows: [],
        active_rollout_id: null,
        can_prepare: true,
        can_custom: false,
        problems: [],
      },
      "POST /tickets/5/rollouts": ro,
      "/rollouts/5": ro,
    });
    renderAt("/tickets/5");
    await userEvent.click(await screen.findByRole("button", { name: /Подготовить раскатку/ }));
    const dialog = await screen.findByRole("dialog", { name: "Раскатка по заявке №5" });
    expect(within(dialog).queryByRole("option", { name: "Произвольная команда" })).not.toBeInTheDocument();
    const pkgs = within(dialog).getByRole("textbox", { name: /^Пакеты/ });
    await userEvent.clear(pkgs);
    await userEvent.type(pkgs, "glibc;reboot");
    expect(within(dialog).getByText(/Недопустимые имена/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Подготовить" })).toBeDisabled();
    await userEvent.clear(pkgs);
    await userEvent.type(pkgs, "glibc");
    await userEvent.click(within(dialog).getByRole("button", { name: "Подготовить" }));
    expect(await screen.findByRole("heading", { name: "Обновить glibc — заявка №42" })).toBeInTheDocument();
    const body = calls.find((c) => c.method === "POST" && c.path === "/tickets/5/rollouts")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ template: "package", manager: "dnf", packages: ["glibc"], hosts: ["10.20.3.32"], canary_host: "10.20.3.32" });
  });
});

describe("исключения", () => {
  beforeEach(() => setToken("t"));
  const meta = {
    approvers: [{ id: 2, username: "manager", display_name: "Петрова А. С." }],
    sync_available: true,
    today: "2026-11-05",
    min_review_on: "2026-11-06",
    max_review_on: "2027-11-05",
    default_review_on: "2027-02-03",
    soon_days: 14,
  };
  const ex: ExceptionOut = {
    id: 9,
    project_id: "p1",
    ticket: { id: 5, title: "Обновить glibc на РЕД ОС 7.3 до 2.35-9.el7", status: "in_progress", severity: "high", os: "РЕД ОС 7.3", kind: "package" },
    kind: "risk_accepted",
    kind_label: "Принятие риска",
    status: "pending",
    status_label: "Ждёт утверждения",
    reason: "Сервер выводится из эксплуатации в декабре",
    measures: "Порт закрыт на МЭ",
    review_on: "2027-02-03",
    days_left: 90,
    review_soon: false,
    requested_by: { id: 7, username: "eng", display_name: "Смирнов Д. В." },
    requested_at: "2026-11-05T10:00:00Z",
    approver: { id: 2, username: "manager", display_name: "Петрова А. С." },
    decided_by: null,
    decided_at: null,
    decision_note: "",
    ended_by: null,
    ended_at: null,
    end_reason: "",
    prev_status: "in_progress",
    hosts: [],
    hosts_now: 2,
    new_hosts: [],
    vuln_count: 0,
    extensions: [],
    sync_scanner: false,
    sync: {},
    created_at: "2026-11-05T10:00:00Z",
    updated_at: "2026-11-05T10:00:00Z",
    can: { approve: true, reject: true, withdraw: false, revoke: false, extend: false, sync: false },
  };

  it("исполнитель оформляет принятие риска: утверждающий, дата пересмотра, меры", async () => {
    const calls = mockApi({
      "/me": engineer,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/tickets/5": { ...detail, can: { ...detail.can, take: false, exception: true } },
      "/tickets/5/history": { history: [], comments: [] },
      "/projects/p1/exception-meta": meta,
      "POST /tickets/5/exceptions": ex,
    });
    renderAt("/tickets/5");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Исключение/ }));
    const dialog = await screen.findByRole("dialog", { name: "Исключение для заявки №5" });
    const submit = within(dialog).getByRole("button", { name: "Отправить на утверждение" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByRole("textbox", { name: /^Обоснование/ }), "Сервер выводится из эксплуатации в декабре");
    await user.type(within(dialog).getByRole("textbox", { name: /Компенсирующие меры/ }), "Порт закрыт на МЭ");
    // Единственный утверждающий выбран сам, дата пересмотра — через 90 дней.
    expect(within(dialog).getByRole("combobox", { name: /^Утверждающий/ })).toHaveValue("2");
    await user.click(submit);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/tickets/5/exceptions")).toBe(true));
    expect(calls.find((c) => c.path === "/tickets/5/exceptions")!.body).toEqual({
      kind: "risk_accepted",
      reason: "Сервер выводится из эксплуатации в декабре",
      measures: "Порт закрыт на МЭ",
      approver_id: 2,
      review_on: "2027-02-03",
      sync_scanner: false,
    });
  });

  it("ложное срабатывание: без даты пересмотра и с отметкой в «Сканере»", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/tickets/5": { ...detail, can: { ...detail.can, take: false, exception: true } },
      "/tickets/5/history": { history: [], comments: [] },
      "/projects/p1/exception-meta": { ...meta, approvers: [...meta.approvers, { id: 3, username: "ciso", display_name: "Белов К. А." }] },
      "POST /tickets/5/exceptions": { ...ex, kind: "false_positive" },
    });
    renderAt("/tickets/5");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Исключение/ }));
    const dialog = await screen.findByRole("dialog", { name: "Исключение для заявки №5" });
    await user.click(within(dialog).getByRole("radio", { name: "Ложное срабатывание" }));
    await user.type(within(dialog).getByRole("textbox", { name: /^Обоснование/ }), "Служба не запущена, пакет не используется");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: /^Утверждающий/ }), "3");
    expect(within(dialog).getByRole("checkbox", { name: /Отметить ложным срабатыванием в «Сканере»/ })).toBeChecked();
    await user.click(within(dialog).getByRole("button", { name: "Отправить на утверждение" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/tickets/5/exceptions")).toBe(true));
    expect(calls.find((c) => c.path === "/tickets/5/exceptions")!.body).toMatchObject({
      kind: "false_positive",
      approver_id: 3,
      review_on: null,
      sync_scanner: true,
    });
  });

  it("утверждающий видит исключение на экране «Исключения» и утверждает его", async () => {
    const calls = mockApi({
      "/me": manager,
      "/projects": [project],
      "/projects/p1/jobs": [],
      "/projects/p1/exception-counts": { pending: 1, to_approve: 1, active: 0, review_soon: 0, ended: 0, all: 1, risk_accepted: 0, false_positive: 0 },
      "/projects/p1/exceptions": [ex],
      "/exceptions/9": ex,
      "POST /exceptions/9/approve": { ...ex, status: "active", status_label: "Действует", can: { ...ex.can, approve: false, reject: false } },
    });
    renderAt("/exceptions");
    expect(await screen.findByText("Сервер выводится из эксплуатации в декабре")).toBeInTheDocument();
    expect(screen.getByText("ждёт вашего решения")).toBeInTheDocument();
    expect(calls.find((c) => c.path.startsWith("/projects/p1/exceptions"))!.path).toContain("state=pending");
    const user = userEvent.setup();
    await user.click(screen.getByText("Сервер выводится из эксплуатации в декабре"));
    const drawer = await screen.findByRole("dialog", { name: "Исключение №9" });
    expect(within(drawer).getByText("Порт закрыт на МЭ")).toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: /Утвердить/ }));
    const dialog = await screen.findByRole("dialog", { name: "Утвердить исключение №9" });
    expect(within(dialog).getByText(/перейдёт в «Принят риск» до 03\.02\.2027/)).toBeInTheDocument();
    await user.type(within(dialog).getByRole("textbox", { name: /Комментарий/ }), "Согласовано");
    await user.click(within(dialog).getByRole("button", { name: "Утвердить" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/exceptions/9/approve")).toBe(true));
    expect(calls.find((c) => c.path === "/exceptions/9/approve")!.body).toEqual({ note: "Согласовано" });
  });
});
