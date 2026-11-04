import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import { mockApi } from "./test/fetchMock";
import { brief, detail, engineer, manager, project } from "./test/fixtures";

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
