"""Мок API «Сканера» на демо-фикстуре: отвечает на HTTP-запросы в тех же формах, что настоящий «Сканер».

Клиент к моку — обычный HttpScannerClient поверх httpx.MockTransport, поэтому разбор ответов
проверяется на тех же формах, что придут от живого «Сканера».

Прицельный прогон считается от «состояния мира» (fixtures/demo.json → world): находки последнего
планового прогона минус уже исправленное администраторами; недоступные хосты и хосты без учётной
записи честно отражаются в покрытии.
"""

import copy
import ipaddress
import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

import httpx

from app.integrations.scanner.client import HttpScannerClient

FIXTURE = Path(__file__).parent / "fixtures" / "demo.json"
COVERAGE_LABELS = {
    "completed": "выполнено",
    "not_applicable": "неприменимо",
    "skipped": "пропущено",
    "unreachable": "хост недоступен",
    "no_credentials": "нет учётной записи",
    "timeout": "таймаут",
    "error": "ошибка",
}
_VENDOR_PKG = re.compile(r"\(пакет ([^)]+)\)|для пакета (\S+)")
_registry: dict[str, "MockScanner"] = {}
_registry_lock = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def vendor_package(finding: dict) -> str | None:
    m = _VENDOR_PKG.search(finding.get("evidence") or "")
    return (m.group(1) or m.group(2)) if m else None


class MockScanner:
    TOKEN = "mock-token"  # noqa: S105 — не секрет, токен мока

    def __init__(self, data: dict | None = None):
        self.data = copy.deepcopy(data) if data is not None else json.loads(FIXTURE.read_text(encoding="utf-8"))
        self._runs: dict[int, dict] = {r["run"]["id"]: r for r in self.data["runs"]}
        self._next_id = max(self._runs) + 900
        self._polls: dict[int, int] = {}
        self._lock = threading.Lock()
        self.requests: list[tuple[str, str, object]] = []
        world = self.data.get("world", {})
        self.patched: set[tuple[str, str]] = {(p["host"], p["package"]) for p in world.get("patched", [])}
        self.unreachable: set[str] = set(world.get("unreachable", []))
        self.no_credentials: set[str] = set(world.get("no_credentials", []))
        # Сколько опросов прицельный прогон остаётся «running» (0 — завершён при первом опросе).
        self.running_polls = 1
        # Отметки «ложное срабатывание»: (договор, dedup_key) → {reason, marked_by, marked_at}.
        self.fp_marks: dict[tuple[int, str], dict] = {}
        # Роль сервисной учётки: без operator отметка ложных срабатываний — 403, как в «Сканере».
        self.can_triage = True

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

    def client(self) -> HttpScannerClient:
        c = HttpScannerClient("https://scanner.mock/api", "svc-vm", "mock", transport=httpx.MockTransport(self.handle))
        c.retry_delay = 0
        return c

    # --- HTTP ---
    def handle(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/api")
        body = json.loads(req.content) if req.content else None
        self.requests.append((req.method, path, body))
        if path == "/auth/token" and req.method == "POST":
            return httpx.Response(200, json={"access_token": self.TOKEN, "token_type": "bearer", "expires_in": 3600})
        if req.headers.get("authorization") != f"Bearer {self.TOKEN}":
            return httpx.Response(401, json={"detail": "not authenticated"})
        params = req.url.params
        routes = [
            ("GET", r"/me", lambda: self.data["me"]),
            ("GET", r"/engagements", lambda: self.data["engagements"]),
            ("GET", r"/engagements/(\d+)", lambda e: self._engagement(int(e))),
            ("GET", r"/engagements/(\d+)/allowlist", lambda e: self._allowlist(int(e))),
            ("GET", r"/engagements/(\d+)/assets", lambda e: self._assets(int(e))),
            ("GET", r"/engagements/(\d+)/asset-groups", lambda e: self._asset_groups(int(e))),
            ("GET", r"/engagements/(\d+)/runs", lambda e: self._run_list(int(e), params)),
            ("POST", r"/engagements/(\d+)/runs", lambda e: self._start_run(int(e), body or {})),
            ("GET", r"/runs/(\d+)", lambda r: self._run_meta(int(r))),
            ("POST", r"/runs/(\d+)/stop", lambda r: self._stop_run(int(r))),
            ("GET", r"/runs/(\d+)/findings", lambda r: self._findings(int(r), params)),
            ("GET", r"/runs/(\d+)/fixes", lambda r: self._fixes(int(r), params)),
            ("GET", r"/runs/(\d+)/coverage", lambda r: self._coverage(int(r))),
            ("PUT", r"/findings/(\d+)/false-positive", lambda f: self._fp_mark(int(f), (body or {}).get("reason"))),
            ("DELETE", r"/findings/(\d+)/false-positive", lambda f: self._fp_unmark(int(f))),
            ("GET", r"/engagements/(\d+)/false-positives", lambda e: self._fp_list(int(e))),
        ]
        for method, rx, fn in routes:
            m = re.fullmatch(rx, path)
            if m and method == req.method:
                try:
                    out = fn(*m.groups())
                except LookupError as e:
                    return httpx.Response(404, json={"detail": str(e)})
                if isinstance(out, httpx.Response):
                    return out
                return httpx.Response(200, json=out)
        return httpx.Response(404, json={"detail": "Not Found"})

    def _engagement(self, eid: int) -> dict:
        for e in self.data["engagements"]:
            if e["id"] == eid:
                return e
        raise LookupError("engagement not found")

    def _allowlist(self, eid: int) -> list[dict]:
        self._engagement(eid)
        return self.data["allowlist"].get(str(eid), [])

    def _assets(self, eid: int) -> list[dict]:
        self._engagement(eid)
        return self.data.get("assets", {}).get(str(eid), [])

    def _asset_groups(self, eid: int) -> list[dict]:
        self._engagement(eid)
        return self.data.get("asset_groups", {}).get(str(eid), [])

    def _get(self, run_id: int) -> dict:
        if run_id not in self._runs:
            raise LookupError("scan run not found")
        return self._runs[run_id]

    def _run_meta(self, run_id: int) -> dict:
        with self._lock:
            meta = self._get(run_id)["run"]
            if meta["status"] == "running":
                left = self._polls.get(run_id, 0)
                if left <= 0:
                    meta.update(
                        status="done",
                        finished_at=_now(),
                        progress={
                            "stage": "done",
                            "percent": 100,
                            "hosts_done": len(meta["targets"]),
                            "hosts_total": len(meta["targets"]),
                        },
                    )
                else:
                    self._polls[run_id] = left - 1
            return copy.deepcopy(meta)

    def _stop_run(self, run_id: int) -> dict:
        """Как в «Сканере»: идущий прогон останавливается, завершённый не меняется."""
        with self._lock:
            meta = self._get(run_id)["run"]
            if meta["status"] in ("pending", "running"):
                meta.update(status="stopped", finished_at=_now())
            return copy.deepcopy(meta)

    def _run_list(self, eid: int, params: httpx.QueryParams) -> httpx.Response:
        self._engagement(eid)
        items = [
            self._run_meta(r) for r in sorted(self._runs, reverse=True) if self._runs[r]["run"]["engagement_id"] == eid
        ]
        if params.get("status"):
            items = [r for r in items if r["status"] == params["status"]]
        off, lim = int(params.get("offset", 0)), int(params.get("limit", 50))
        return httpx.Response(200, json=items[off : off + lim], headers={"X-Total-Count": str(len(items))})

    def _findings(self, run_id: int, params: httpx.QueryParams) -> httpx.Response:
        r = self._get(run_id)
        eid = r["run"]["engagement_id"]
        items = [{**f, "false_positive": self.fp_marks.get((eid, f["dedup_key"]))} for f in r["findings"]]
        off = int(params.get("offset", 0))
        lim = min(int(params.get("limit", 1000)), 1000)
        return httpx.Response(200, json=items[off : off + lim], headers={"X-Total-Count": str(len(items))})

    def _fixes(self, run_id: int, params: httpx.QueryParams) -> dict:
        r = self._get(run_id)
        tasks = self._without_fp(r)
        off = int(params.get("offset", 0))
        lim = min(int(params.get("limit", 50)), 500)
        kinds: dict[str, int] = {}
        oss: dict[str, int] = {}
        sevs: dict[str, int] = {}
        for t in tasks:
            kinds[t["kind"]] = kinds.get(t["kind"], 0) + 1
            oss[t["os"] or "-"] = oss.get(t["os"] or "-", 0) + 1
            sevs[t["severity"]] = sevs.get(t["severity"], 0) + 1
        return {
            "total": len(tasks),
            "items": tasks[off : off + lim],
            "tasks": len(tasks),
            "hosts": len({h["host"] for t in tasks for h in t["hosts"]}),
            "findings": sum(t["finding_count"] for t in tasks),
            "false_positives": sum(
                1 for f in r["findings"] if (r["run"]["engagement_id"], f["dedup_key"]) in self.fp_marks
            ),
            "kinds": kinds,
            "os": oss,
            "severities": sevs,
        }

    def _without_fp(self, r: dict) -> list[dict]:
        """«Что исправить» без находок, отмеченных ложными, — как в «Сканере» (fixplan)."""
        eid = r["run"]["engagement_id"]
        fp_ids = {f["id"] for f in r["findings"] if (eid, f["dedup_key"]) in self.fp_marks}
        if not fp_ids:
            return r["fixes"]
        out = []
        for fx in r["fixes"]:
            hosts = []
            for h in fx["hosts"]:
                refs = [ref for ref in h["findings"] if ref["id"] not in fp_ids]
                if refs:
                    hosts.append({**h, "findings": refs})
            if hosts:
                n = sum(len(h["findings"]) for h in hosts)
                out.append({**fx, "hosts": hosts, "host_count": len(hosts), "finding_count": n})
        return out

    # --- ложные срабатывания ---
    def _finding(self, finding_id: int) -> tuple[int, dict]:
        # В фикстуре номера находок разных прогонов пересекаются (в «Сканере» они уникальны) —
        # ищем с последнего прогона: «Устранение» хранит номер из последнего импорта.
        for _, r in sorted(self._runs.items(), reverse=True):
            for f in r["findings"]:
                if f["id"] == finding_id:
                    return r["run"]["engagement_id"], f
        raise LookupError("finding not found")

    def _fp_mark(self, finding_id: int, reason: str | None) -> dict | httpx.Response:
        if not self.can_triage:
            return httpx.Response(403, json={"detail": "insufficient permissions"})
        eid, f = self._finding(finding_id)
        mark = {"reason": (reason or "").strip() or None, "marked_by": "svc-vm", "marked_at": _now()}
        with self._lock:
            self.fp_marks[(eid, f["dedup_key"])] = mark
        return {**f, "false_positive": mark}

    def _fp_unmark(self, finding_id: int) -> dict | httpx.Response:
        if not self.can_triage:
            return httpx.Response(403, json={"detail": "insufficient permissions"})
        eid, f = self._finding(finding_id)
        with self._lock:
            if self.fp_marks.pop((eid, f["dedup_key"]), None) is None:
                return httpx.Response(404, json={"detail": "finding is not marked as false positive"})
        return {**f, "false_positive": None}

    def _fp_list(self, eid: int) -> list[dict]:
        self._engagement(eid)
        out = []
        seen: dict[str, dict] = {}
        for r in self._runs.values():
            if r["run"]["engagement_id"] == eid:
                for f in r["findings"]:
                    seen.setdefault(f["dedup_key"], f)
        for (e, key), m in self.fp_marks.items():
            if e != eid or key not in seen:
                continue
            f = seen[key]
            out.append(
                {
                    "dedup_key": key,
                    "host": f["host"],
                    "port": f["port"],
                    "vuln_id": f["vuln_id"],
                    "module": f["module"],
                    "title": f["title"],
                    **m,
                }
            )
        return out

    def _coverage(self, run_id: int) -> dict:
        r = self._get(run_id)
        entries = r["coverage_entries"]
        hosts = []
        for h in dict.fromkeys(e["host"] for e in entries):
            per = {
                e["module"]: {"status": e["status"], "label": e["label"], "reason": e["reason"]}
                for e in entries
                if e["host"] == h
            }
            sts = {v["status"] for v in per.values()}
            status = (
                "checked"
                if sts <= {"completed", "not_applicable"}
                else ("unreachable" if sts == {"unreachable"} else "partial")
            )
            hosts.append({"host": h, "status": status, "modules": per})
        counts = {s: sum(1 for e in entries if e["status"] == s) for s in COVERAGE_LABELS}
        summary = {
            "hosts": len(hosts),
            "hosts_checked": sum(h["status"] == "checked" for h in hosts),
            "hosts_partial": sum(h["status"] == "partial" for h in hosts),
            "hosts_unreachable": sum(h["status"] == "unreachable" for h in hosts),
            "hosts_not_checked": 0,
            "counts": counts,
        }
        return {
            "scan_run_id": run_id,
            "status": r["run"]["status"],
            "summary": summary,
            "hosts": hosts,
            "entries": entries,
            "legacy": False,
        }

    # --- прицельный прогон ---
    def _start_run(self, eid: int, body: dict) -> httpx.Response:
        nets = [ipaddress.ip_network(c, strict=False) for c in (a["cidr"] for a in self._allowlist(eid))]
        accepted, denied = [], []
        for t in body.get("targets", []):
            try:
                ok = any(ipaddress.ip_address(t) in n for n in nets)
            except ValueError:
                ok = False
            if ok:
                accepted.append(t)
            else:
                denied.append({"target": t, "reason": "вне allowlist договора", "count": 1})
        if not accepted:
            return httpx.Response(
                422,
                json={
                    "detail": {
                        "message": "no requested target is in the engagement allowlist",
                        "denied_targets": denied,
                    }
                },
            )
        modules = list(body.get("modules") or [])
        base = self._get(self.data["world"]["base_run_id"])
        with self._lock:
            self._next_id += 1
            run_id = self._next_id
        reachable = {h for h in accepted if h not in self.unreachable}
        kept: dict[int, dict] = {}
        for f in base["findings"]:
            if f["host"] not in reachable or f["module"] not in modules:
                continue
            if f["module"] == "auth_inventory" and f["host"] in self.no_credentials:
                continue
            if (f["host"], vendor_package(f)) in self.patched:
                continue
            nf = copy.deepcopy(f)
            nf.update(id=run_id * 10 + len(kept) + 1, status="open", detected_at=_now())
            kept[f["id"]] = nf
        fixes = []
        for fx in base["fixes"]:
            hosts = []
            for h in fx["hosts"]:
                refs = [{**ref, "id": kept[ref["id"]]["id"]} for ref in h["findings"] if ref["id"] in kept]
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
        entries = []
        for h in accepted:
            for m in modules:
                if h in self.unreachable:
                    st, reason = "unreachable", "хост не ответил на пробы обнаружения"
                elif m in ("auth_inventory", "config_audit") and h in self.no_credentials:
                    st, reason = "no_credentials", "нет учётной записи для входа по SSH"
                else:
                    st, reason = "completed", None
                entries.append({"host": h, "module": m, "status": st, "label": COVERAGE_LABELS[st], "reason": reason})
        meta = {
            "id": run_id,
            "engagement_id": eid,
            "modules": modules,
            "rate_profile": body.get("rate_profile", "gentle"),
            "credential_ids": body.get("credential_ids", []),
            "cred_set_ids": [],
            "name": body.get("name"),
            "targets": accepted,
            "schedule_id": None,
            "status": "running",
            "started_by": 99,
            "started_at": _now(),
            "finished_at": None,
            "created_at": _now(),
            "error_message": None,
            "retry_of": None,
            "options": {"no_ping": False, "profile": body.get("profile")},
            "warnings": [],
            "progress": {"stage": "vuln", "percent": 10, "hosts_done": 0, "hosts_total": len(accepted)},
        }
        with self._lock:
            self._runs[run_id] = {
                "run": meta,
                "findings": list(kept.values()),
                "fixes": fixes,
                "coverage_entries": entries,
            }
            self._polls[run_id] = self.running_polls
        return httpx.Response(
            202, json={**copy.deepcopy(meta), "accepted_targets": len(accepted), "denied_targets": denied}
        )
