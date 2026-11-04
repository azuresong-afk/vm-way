"""Клиент API «Сканера» (Bearer-токен сервисной учётной записи)."""

import threading
import time
from typing import Any, Protocol

import httpx

# Завершённые прогоны — все, кроме pending/running.
FINISHED_STATUSES = {"done", "partial", "failed", "stopped", "interrupted"}
PAGE = 500


class ScannerError(Exception):
    """Ошибка обращения к «Сканеру» (текст безопасен для показа пользователю)."""


class ScannerClient(Protocol):
    def me(self) -> dict: ...
    def engagements(self) -> list[dict]: ...
    def engagement(self, engagement_id: int) -> dict: ...
    def allowlist(self, engagement_id: int) -> list[str]: ...
    def runs(self, engagement_id: int, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]: ...
    def run(self, run_id: int) -> dict: ...
    def findings(self, run_id: int) -> list[dict]: ...
    def fixes(self, run_id: int) -> list[dict]: ...
    def coverage(self, run_id: int) -> list[dict]: ...
    def start_run(self, engagement_id: int, body: dict) -> dict: ...


class HttpScannerClient:
    """Реализация по HTTP. Токен получается по логину/паролю и обновляется при 401."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._token: str | None = None
        self._lock = threading.Lock()
        self._http = httpx.Client(base_url=self.base_url, verify=verify_tls, timeout=timeout, transport=transport)
        self.retry_delay = 1.0

    def close(self) -> None:
        self._http.close()

    def _login(self) -> None:
        try:
            r = self._http.post("/auth/token", json={"username": self._username, "password": self._password})
        except httpx.HTTPError as e:
            raise ScannerError(f"«Сканер» недоступен: {type(e).__name__}") from e
        if r.status_code != 200:
            raise ScannerError(f"Вход в «Сканер» не выполнен (HTTP {r.status_code})")
        self._token = r.json()["access_token"]

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        for attempt in range(3):
            with self._lock:
                if not self._token:
                    self._login()
                headers = {"Authorization": f"Bearer {self._token}"}
            try:
                r = self._http.request(method, path, headers=headers, **kw)
            except httpx.HTTPError as e:
                if attempt == 2:
                    raise ScannerError(f"«Сканер» недоступен: {type(e).__name__}") from e
                time.sleep(self.retry_delay * (1 + attempt))
                continue
            if r.status_code == 401 and attempt == 0:
                self._token = None
                continue
            if r.status_code >= 500 and attempt < 2:
                time.sleep(self.retry_delay * (1 + attempt))
                continue
            if r.status_code >= 400:
                raise ScannerError(f"«Сканер» ответил HTTP {r.status_code} на {method} {path}")
            return r
        raise ScannerError("«Сканер» не ответил")

    def _get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None}).json()

    def _paged(self, path: str, **params: Any) -> list[dict]:
        out: list[dict] = []
        offset = 0
        while True:
            r = self._request("GET", path, params={**params, "limit": PAGE, "offset": offset})
            batch = r.json()
            items = batch if isinstance(batch, list) else batch.get("items", [])
            out.extend(items)
            total = int(r.headers.get("X-Total-Count", len(out)))
            offset += len(items)
            if not items or offset >= total:
                return out

    def me(self) -> dict:
        return self._get("/me")

    def engagements(self) -> list[dict]:
        data = self._get("/engagements")
        return data if isinstance(data, list) else data.get("items", [])

    def engagement(self, engagement_id: int) -> dict:
        return self._get(f"/engagements/{engagement_id}")

    def allowlist(self, engagement_id: int) -> list[str]:
        data = self._get(f"/engagements/{engagement_id}/allowlist")
        if isinstance(data, dict):
            data = data.get("items", data.get("targets", []))
        return [x if isinstance(x, str) else x.get("target", x.get("value", "")) for x in data]

    def runs(self, engagement_id: int, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        data = self._get(f"/engagements/{engagement_id}/runs", status=status, limit=limit, offset=offset)
        return data if isinstance(data, list) else data.get("items", [])

    def run(self, run_id: int) -> dict:
        return self._get(f"/runs/{run_id}")

    def findings(self, run_id: int) -> list[dict]:
        return self._paged(f"/runs/{run_id}/findings")

    def fixes(self, run_id: int) -> list[dict]:
        data = self._get(f"/runs/{run_id}/fixes")
        return data if isinstance(data, list) else data.get("items", data.get("actions", []))

    def coverage(self, run_id: int) -> list[dict]:
        data = self._get(f"/runs/{run_id}/coverage")
        return normalize_coverage(data)

    def start_run(self, engagement_id: int, body: dict) -> dict:
        return self._request("POST", f"/engagements/{engagement_id}/runs", json=body).json()


def normalize_coverage(data: Any) -> list[dict]:
    """Покрытие → плоский список {host, module, status, reason}.

    Принимает и плоский список, и вложенную форму {hosts: [{host, modules: {module: status}}]}.
    """
    if isinstance(data, dict):
        data = data.get("items", data.get("hosts", []))
    out: list[dict] = []
    for row in data or []:
        if "module" in row:
            out.append(
                {
                    "host": row["host"],
                    "module": row["module"],
                    "status": row.get("status", ""),
                    "reason": row.get("reason", "") or "",
                }
            )
            continue
        modules = row.get("modules", {})
        items = modules.items() if isinstance(modules, dict) else ((m["module"], m) for m in modules)
        for module, st in items:
            status = st if isinstance(st, str) else st.get("status", "")
            reason = "" if isinstance(st, str) else st.get("reason", "") or ""
            out.append({"host": row["host"], "module": module, "status": status, "reason": reason})
    return out


def make_client(base_url: str, username: str = "", password: str = "", verify_tls: bool = True) -> ScannerClient:
    """Источник с адресом mock://<имя> работает на встроенном моке (демо и тесты)."""
    if base_url.startswith("mock://"):
        from app.integrations.scanner.mock import MockScanner

        return MockScanner.shared(base_url[len("mock://") :] or "demo")
    if not base_url.startswith(("http://", "https://")):
        raise ScannerError("Адрес API «Сканера» должен начинаться с https:// или http://")
    return HttpScannerClient(base_url, username, password, verify_tls)
