"""Клиент API «Сканера» (Bearer-токен сервисной учётной записи).

Формы ответов сверены с кодом «Сканера» (scanner/api/schemas.py):
- GET /runs/{id}/findings — список FindingOut, всего — X-Total-Count, limit ≤ 1000;
- GET /runs/{id}/fixes — FixPlanOut {total, items, …}, limit ≤ 500;
- GET /runs/{id}/coverage — CoverageOut {entries: [{host, module, status, label, reason}], hosts, …};
- GET /engagements/{id}/allowlist — список AllowlistOut {id, cidr, …};
- GET /engagements/{id}/assets — список AssetOut {id, address, hostname, owner, criticality, tags[],
  groups[{id, name}], …} без пагинации;
- GET /engagements/{id}/asset-groups — список AssetGroupOut {id, name, asset_count, …};
- POST /engagements/{id}/runs — RunCreated (RunOut + accepted_targets: int, denied_targets: [{target, reason, count}]),
  ни одной разрешённой цели — 422;
- PUT /findings/{id}/false-positive {reason} — FindingOut с false_positive; DELETE — снять отметку
  (404, если отметки нет). Нужна роль operator (право triage_findings). Отметка — по (договор, dedup_key).
"""

import threading
import time
from typing import Any, Protocol

import httpx

# Завершённые прогоны — все, кроме pending/running (repository.FINISHED_RUN_STATUSES).
FINISHED_STATUSES = frozenset({"done", "partial", "failed", "stopped", "interrupted"})
FINDINGS_PAGE = 1000
FIXES_PAGE = 500


class ScannerError(Exception):
    """Ошибка обращения к «Сканеру» (текст безопасен для показа пользователю)."""

    def __init__(self, message: str, status: int | None = None, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class ScannerClient(Protocol):
    def me(self) -> dict: ...
    def engagements(self) -> list[dict]: ...
    def engagement(self, engagement_id: int) -> dict: ...
    def allowlist(self, engagement_id: int) -> list[str]: ...
    def assets(self, engagement_id: int) -> list[dict]: ...
    def asset_groups(self, engagement_id: int) -> list[dict]: ...
    def runs(self, engagement_id: int, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]: ...
    def run(self, run_id: int) -> dict: ...
    def findings(self, run_id: int) -> list[dict]: ...
    def fixes(self, run_id: int) -> list[dict]: ...
    def coverage(self, run_id: int) -> list[dict]: ...
    def start_run(self, engagement_id: int, body: dict) -> dict: ...
    def mark_false_positive(self, finding_id: int, reason: str | None) -> dict: ...
    def unmark_false_positive(self, finding_id: int) -> bool: ...


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
            raise ScannerError(f"Вход в «Сканер» не выполнен (HTTP {r.status_code})", r.status_code)
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
                try:
                    detail = r.json().get("detail")
                except ValueError:
                    detail = None
                raise ScannerError(f"«Сканер» ответил HTTP {r.status_code} на {method} {path}", r.status_code, detail)
            return r
        raise ScannerError("«Сканер» не ответил")

    def _get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None}).json()

    def me(self) -> dict:
        return self._get("/me")

    def engagements(self) -> list[dict]:
        return self._get("/engagements")

    def engagement(self, engagement_id: int) -> dict:
        return self._get(f"/engagements/{engagement_id}")

    def allowlist(self, engagement_id: int) -> list[str]:
        return [row["cidr"] for row in self._get(f"/engagements/{engagement_id}/allowlist")]

    def assets(self, engagement_id: int) -> list[dict]:
        return self._get(f"/engagements/{engagement_id}/assets")

    def asset_groups(self, engagement_id: int) -> list[dict]:
        return self._get(f"/engagements/{engagement_id}/asset-groups")

    def runs(self, engagement_id: int, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        return self._get(f"/engagements/{engagement_id}/runs", status=status, limit=limit, offset=offset)

    def run(self, run_id: int) -> dict:
        return self._get(f"/runs/{run_id}")

    def findings(self, run_id: int) -> list[dict]:
        out: list[dict] = []
        while True:
            r = self._request("GET", f"/runs/{run_id}/findings", params={"limit": FINDINGS_PAGE, "offset": len(out)})
            batch = r.json()
            out.extend(batch)
            total = int(r.headers.get("X-Total-Count", len(out)))
            if not batch or len(out) >= total:
                return out

    def fixes(self, run_id: int) -> list[dict]:
        out: list[dict] = []
        while True:
            page = self._get(f"/runs/{run_id}/fixes", limit=FIXES_PAGE, offset=len(out))
            out.extend(page["items"])
            if not page["items"] or len(out) >= page["total"]:
                return out

    def coverage(self, run_id: int) -> list[dict]:
        return normalize_coverage(self._get(f"/runs/{run_id}/coverage"))

    def start_run(self, engagement_id: int, body: dict) -> dict:
        return self._request("POST", f"/engagements/{engagement_id}/runs", json=body).json()

    def mark_false_positive(self, finding_id: int, reason: str | None) -> dict:
        return self._request("PUT", f"/findings/{finding_id}/false-positive", json={"reason": reason}).json()

    def unmark_false_positive(self, finding_id: int) -> bool:
        """Снять отметку. False — отметки и так не было (404 «not marked»)."""
        try:
            self._request("DELETE", f"/findings/{finding_id}/false-positive")
        except ScannerError as e:
            if e.status == 404 and "not marked" in str(e.detail or ""):
                return False
            raise
        return True


def normalize_coverage(data: dict) -> list[dict]:
    """CoverageOut → плоский список {host, module, status, reason}."""
    return [
        {"host": e["host"], "module": e["module"], "status": e["status"], "reason": e.get("reason") or ""}
        for e in data.get("entries", [])
    ]


def make_client(base_url: str, username: str = "", password: str = "", verify_tls: bool = True) -> ScannerClient:
    """Источник с адресом mock://<имя> работает на встроенном моке API «Сканера» (демо и тесты)."""
    if base_url.startswith("mock://"):
        from app.integrations.scanner.mock import MockScanner

        return MockScanner.shared(base_url[len("mock://") :] or "demo").client()
    if not base_url.startswith(("http://", "https://")):
        raise ScannerError("Адрес API «Сканера» должен начинаться с https:// или http://")
    return HttpScannerClient(base_url, username, password, verify_tls)
