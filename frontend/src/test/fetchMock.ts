import { vi } from "vitest";

type Handler = (url: URL, init?: RequestInit) => unknown;

/** Подмена fetch: ответы по префиксу пути (без /api), список — с X-Total-Count. */
export function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { method: string; path: string; body: unknown }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const path = url.pathname.replace(/^\/api/, "");
    const method = init?.method ?? "GET";
    calls.push({ method, path: path + url.search, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const key = Object.keys(routes)
      .filter((k) => {
        const [m, p] = k.includes(" ") ? k.split(" ") : ["GET", k];
        return m === method && (path === p || path.startsWith(p + "?"));
      })
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return new Response(JSON.stringify({ detail: `нет мока для ${method} ${path}` }), { status: 404 });
    const r = routes[key];
    const data = typeof r === "function" ? (r as Handler)(url, init) : r;
    if (data instanceof Response) return data; // обработчик сам задал статус
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (Array.isArray(data)) headers["X-Total-Count"] = String(data.length);
    return new Response(JSON.stringify(data), { status: 200, headers });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}
