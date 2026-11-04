"""Мок «Сканера» на демо-фикстуре: плановые прогоны и прицельные проверки.

Прицельный прогон считается от «состояния мира» (fixtures/demo.json → world):
находки последнего планового прогона минус уже исправленное администраторами;
недоступные хосты и хосты без учётной записи честно отражаются в покрытии.
"""

import copy
import ipaddress
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from app.integrations.scanner.client import ScannerError

FIXTURE = Path(__file__).parent / "fixtures" / "demo.json"
_registry: dict[str, "MockScanner"] = {}
_registry_lock = threading.Lock()


class MockScanner:
    def __init__(self, data: dict | None = None):
        self.data = copy.deepcopy(data) if data is not None else json.loads(FIXTURE.read_text(encoding="utf-8"))
        self._runs: dict[int, dict] = {r["run"]["id"]: r for r in self.data["runs"]}
        self._next_id = max(self._runs) + 900
        self._polls: dict[int, int] = {}
        self._lock = threading.Lock()
        self.calls: list[tuple[str, object]] = []
        world = self.data.get("world", {})
        self.patched: set[tuple[str, str]] = {(p["host"], p["package"]) for p in world.get("patched", [])}
        self.unreachable: set[str] = set(world.get("unreachable", []))
        self.no_credentials: set[str] = set(world.get("no_credentials", []))
        # Сколько опросов прицельный прогон остаётся «running» (0 — сразу завершён).
        self.running_polls = 1

    @classmethod
    def shared(cls, name: str = "demo") -> "MockScanner":
        with _registry_lock:
            if name not in _registry:
                _registry[name] = cls()
            return _registry[name]

    @classmethod
    def reset(cls) -> None:
        with _registry_lock:
            _registry.clear()

    # --- чтение ---
    def me(self) -> dict:
        return {
            "id": 99,
            "username": "svc-vm",
            "display_name": "Сервисная учётная запись «Устранения»",
            "roles": ["auditor", "operator"],
            "permissions": ["host_credentials"],
        }

    def engagements(self) -> list[dict]:
        return copy.deepcopy(self.data["engagements"])

    def engagement(self, engagement_id: int) -> dict:
        for e in self.data["engagements"]:
            if e["id"] == engagement_id:
                return copy.deepcopy(e)
        raise ScannerError(f"Проект «Сканера» {engagement_id} не найден")

    def allowlist(self, engagement_id: int) -> list[str]:
        self.engagement(engagement_id)
        return list(self.data["allowlist"].get(str(engagement_id), []))

    def runs(self, engagement_id: int, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        items = [
            self.run(r)
            for r in sorted(self._runs, reverse=True)
            if self._runs[r]["run"]["engagement_id"] == engagement_id
        ]
        if status:
            items = [r for r in items if r["status"] == status]
        return items[offset : offset + limit]

    def _get(self, run_id: int) -> dict:
        if run_id not in self._runs:
            raise ScannerError(f"«Сканер» ответил HTTP 404 на GET /runs/{run_id}")
        return self._runs[run_id]

    def run(self, run_id: int) -> dict:
        with self._lock:
            r = self._get(run_id)
            meta = r["run"]
            if meta["status"] == "running":
                left = self._polls.get(run_id, 0)
                if left <= 0:
                    meta["status"] = "done"
                    meta["progress"] = 100
                    meta["finished_at"] = _now()
                else:
                    self._polls[run_id] = left - 1
            return copy.deepcopy(meta)

    def findings(self, run_id: int) -> list[dict]:
        return copy.deepcopy(self._get(run_id)["findings"])

    def fixes(self, run_id: int) -> list[dict]:
        return copy.deepcopy(self._get(run_id)["fixes"])

    def coverage(self, run_id: int) -> list[dict]:
        return copy.deepcopy(self._get(run_id)["coverage"])

    # --- прицельный прогон ---
    def start_run(self, engagement_id: int, body: dict) -> dict:
        self.calls.append(("start_run", copy.deepcopy(body)))
        nets = [ipaddress.ip_network(n, strict=False) for n in self.allowlist(engagement_id)]
        accepted, denied = [], []
        for t in body.get("targets", []):
            try:
                ok = any(ipaddress.ip_address(t) in n for n in nets)
            except ValueError:
                ok = False
            (accepted if ok else denied).append(t)
        if not accepted:
            raise ScannerError("«Сканер» ответил HTTP 422: все цели вне allowlist")
        modules = list(body.get("modules") or [])
        base = self._get(self.data["world"]["base_run_id"])
        with self._lock:
            self._next_id += 1
            run_id = self._next_id
        reachable = [h for h in accepted if h not in self.unreachable]
        findings, keep_ids = [], set()
        for f in base["findings"]:
            if f["host"] not in reachable or f["module"] not in modules:
                continue
            if f["module"] == "auth_inventory" and f["host"] in self.no_credentials:
                continue
            if (f["host"], f["software"]) in self.patched:
                continue
            nf = copy.deepcopy(f)
            nf["id"] = run_id * 10 + len(findings) + 1
            keep_ids.add(f["id"])
            findings.append((f["id"], nf))
        id_map = {old: new["id"] for old, new in findings}
        fixes = []
        for fx in base["fixes"]:
            hosts = []
            for h in fx["hosts"]:
                refs = [{**ref, "id": id_map[ref["id"]]} for ref in h["findings"] if ref["id"] in keep_ids]
                if refs:
                    hosts.append({**h, "findings": refs})
            if hosts:
                fixes.append(
                    {
                        **copy.deepcopy(fx),
                        "hosts": hosts,
                        "host_count": len(hosts),
                        "finding_count": sum(len(h["findings"]) for h in hosts),
                    }
                )
        coverage = []
        for h in accepted:
            for m in modules:
                if h in self.unreachable:
                    st, reason = "unreachable", "Хост не ответил на запросы"
                elif m in ("auth_inventory", "config_audit") and h in self.no_credentials:
                    st, reason = "no_credentials", "Нет учётной записи для входа по SSH"
                else:
                    st, reason = "completed", ""
                coverage.append({"host": h, "module": m, "status": st, "reason": reason})
        meta = {
            "id": run_id,
            "engagement_id": engagement_id,
            "name": body.get("name", ""),
            "modules": modules,
            "targets": accepted,
            "status": "running",
            "started_at": _now(),
            "finished_at": None,
            "progress": 10,
            "warnings": [],
            "options": {k: v for k, v in body.items() if k not in ("targets", "modules")},
        }
        with self._lock:
            self._runs[run_id] = {
                "run": meta,
                "findings": [nf for _, nf in findings],
                "fixes": fixes,
                "coverage": coverage,
            }
            self._polls[run_id] = self.running_polls
        return {**copy.deepcopy(meta), "accepted_targets": accepted, "denied_targets": denied}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
