"""Адаптер «Сканера»: мок API на фикстуре, сверка с контрактом и HTTP-клиент."""

import hashlib
import json

import httpx
import pytest

from app.integrations.scanner import FINISHED_STATUSES, HttpScannerClient, MockScanner, ScannerError, make_client
from app.integrations.scanner.fixtures import generate
from tests import scanner_contract as sc


@pytest.fixture()
def mock():
    m = MockScanner()
    m.running_polls = 0
    return m


@pytest.fixture()
def raw(mock):
    """Сырые ответы мока по HTTP (как их видит клиент)."""
    http = httpx.Client(base_url="https://scanner.mock/api", transport=httpx.MockTransport(mock.handle))
    http.headers["Authorization"] = f"Bearer {MockScanner.TOKEN}"
    return http


# --- контракт: ответы мока совпадают со схемами «Сканера» ---


def test_contract_reads(raw):
    sc.MeOut.model_validate(raw.get("/me").json())
    for e in raw.get("/engagements").json():
        sc.EngagementOut.model_validate(e)
    for a in raw.get("/engagements/7/allowlist").json():
        sc.AllowlistOut.model_validate(a)
    runs = raw.get("/engagements/7/runs").json()
    assert [r["id"] for r in runs] == [102, 101, 100]
    for r in runs:
        assert sc.RunOut.model_validate(r).status in sc.RUN_STATUSES


@pytest.mark.parametrize("run_id", [100, 101, 102])
def test_contract_run_results(raw, run_id):
    r = raw.get(f"/runs/{run_id}/findings", params={"limit": 1000})
    assert int(r.headers["X-Total-Count"]) == len(r.json())
    for f in r.json():
        f = sc.FindingOut.model_validate(f)
        assert f.severity in sc.SEVERITIES and f.status in sc.FINDING_STATUSES
        assert f.priority.label in sc.PRIORITY_LABELS
    plan = sc.FixPlanOut.model_validate(raw.get(f"/runs/{run_id}/fixes", params={"limit": 500}).json())
    assert plan.total == len(plan.items)
    assert all(t.kind in sc.FIX_KINDS for t in plan.items)
    cov = sc.CoverageOut.model_validate(raw.get(f"/runs/{run_id}/coverage").json())
    assert all(e.status in sc.COVERAGE_STATUSES for e in cov.entries)


def test_contract_start_run(raw):
    r = raw.post("/engagements/7/runs", json={"targets": ["10.20.1.11", "8.8.8.8"], "modules": ["auth_inventory"]})
    assert r.status_code == 202
    created = sc.RunCreated.model_validate(r.json())
    assert created.accepted_targets == 1 and created.denied_targets[0].target == "8.8.8.8"
    bad = raw.post("/engagements/7/runs", json={"targets": ["8.8.8.8"], "modules": ["vuln"]})
    assert bad.status_code == 422 and bad.json()["detail"]["denied_targets"]


def test_fix_keys_and_dedup_match_scanner_algorithms(mock):
    c = mock.client()
    f = next(x for x in c.findings(100) if x["host"] == "10.20.1.11" and x["software"] == "OpenSSH")
    raw = f"{f['host']}|{f['port']}|{f['vuln_id']}|{f['module']}"
    assert f["dedup_key"] == hashlib.sha256(raw.encode()).hexdigest()
    fx = next(x for x in c.fixes(100) if x["os_family"] == "debian" and x["packages"] == ["openssh-server"])
    expected = hashlib.sha1("\x1f".join(["package", "('debian', '12')", "openssh"]).encode()).hexdigest()[:16]  # noqa: S324
    assert fx["key"] == expected


def test_fixture_is_generated():
    from app.integrations.scanner.mock import FIXTURE

    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == json.loads(json.dumps(generate.build()))


# --- клиент поверх мока ---


def test_fixture_shape(mock):
    c = mock.client()
    hosts = mock.data["hosts"]
    assert len(hosts) == 20 and len({h["os_family"] for h in hosts}) == 3
    assert c.allowlist(7) == ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]
    assert all(r["status"] in FINISHED_STATUSES for r in c.runs(7))


def test_dedup_key_is_stable_between_runs(mock):
    c = mock.client()
    keys = {r: {f["dedup_key"] for f in c.findings(r)} for r in (100, 101, 102)}
    ssh = next(f for f in c.findings(100) if f["host"] == "10.20.1.11" and f["software"] == "OpenSSH")
    assert all(ssh["dedup_key"] in keys[r] for r in (100, 101, 102))


def test_fixes_reference_findings_and_cover_3_os(mock):
    c = mock.client()
    ids = {f["id"] for f in c.findings(102)}
    fixes = c.fixes(102)
    assert {fx["os_family"] for fx in fixes if fx["os_family"]} == {"debian", "astra", "redos"}
    for fx in fixes:
        assert fx["host_count"] == len(fx["hosts"])
        for h in fx["hosts"]:
            assert {ref["id"] for ref in h["findings"]} <= ids


def test_regression_and_unreachable_in_fixture(mock):
    c = mock.client()
    statuses = {(f["host"], f["software"]): f["status"] for f in c.findings(102)}
    assert statuses[("10.20.1.18", "Expat")] == "regression"
    cov = [e for e in c.coverage(102) if e["host"] == "10.20.3.36"]
    assert cov and all(e["status"] == "unreachable" for e in cov)
    assert not [f for f in c.findings(102) if f["host"] == "10.20.3.36"]


def test_targeted_run(mock):
    c = mock.client()
    ssh = next(fx for fx in c.fixes(102) if fx["packages"] == ["openssh-server"] and fx["os_family"] == "debian")
    targets = [h["host"] for h in ssh["hosts"]] + ["192.168.99.1"]
    started = c.start_run(
        7, {"targets": targets, "modules": ["auth_inventory"], "credential_ids": [3], "name": "Проверка устранения: №1"}
    )
    assert started["denied_targets"] == [{"target": "192.168.99.1", "reason": "вне allowlist договора", "count": 1}]
    assert started["accepted_targets"] == 8 and started["status"] == "running"
    assert c.run(started["id"])["status"] == "done"
    left = {f["host"] for f in c.findings(started["id"]) if f["software"] == "OpenSSH"}
    # Исправлены web-01..04 и app-01; app-02 и db-01 — нет; mon-01 недоступен.
    assert left == {"10.20.1.16", "10.20.1.17"}
    cov = {e["host"]: e["status"] for e in c.coverage(started["id"])}
    assert cov["10.20.1.18"] == "unreachable" and cov["10.20.1.11"] == "completed"


def test_targeted_run_no_credentials(mock):
    c = mock.client()
    started = c.start_run(7, {"targets": ["10.20.2.26"], "modules": ["auth_inventory"]})
    assert c.coverage(started["id"])[0]["status"] == "no_credentials"
    assert c.findings(started["id"]) == []


def test_targeted_run_all_denied(mock):
    with pytest.raises(ScannerError) as e:
        mock.client().start_run(7, {"targets": ["8.8.8.8"], "modules": ["vuln"]})
    assert e.value.status == 422 and e.value.detail["denied_targets"][0]["target"] == "8.8.8.8"


def test_make_client():
    a = make_client("mock://demo")
    assert isinstance(a, HttpScannerClient) and a.me()["username"] == "svc-vm"
    with pytest.raises(ScannerError):
        make_client("ftp://x")


# --- HTTP-клиент на подменённом транспорте ---


def _http_scanner(handler):
    c = HttpScannerClient("https://scanner.local/api", "svc", "pw", transport=httpx.MockTransport(handler))
    c.retry_delay = 0
    return c


def test_http_login_pagination_and_reauth():
    state = {"logins": 0, "expired_once": False}
    items = [{"id": i} for i in range(2500)]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/auth/token"):
            assert json.loads(req.content) == {"username": "svc", "password": "pw"}
            state["logins"] += 1
            return httpx.Response(200, json={"access_token": f"t{state['logins']}", "token_type": "bearer"})
        assert req.headers["authorization"].startswith("Bearer t")
        if not state["expired_once"]:
            state["expired_once"] = True
            return httpx.Response(401)
        off, lim = int(req.url.params["offset"]), int(req.url.params["limit"])
        assert lim <= 1000
        return httpx.Response(200, json=items[off : off + lim], headers={"X-Total-Count": str(len(items))})

    c = _http_scanner(handler)
    assert len(c.findings(5)) == 2500
    assert state["logins"] == 2  # повторный вход после 401


def test_http_fixes_paginated():
    tasks = [{"key": str(i)} for i in range(1200)]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t"})
        off, lim = int(req.url.params["offset"]), int(req.url.params["limit"])
        assert lim <= 500
        return httpx.Response(200, json={"total": len(tasks), "items": tasks[off : off + lim]})

    assert len(_http_scanner(handler).fixes(1)) == 1200


def test_http_errors_are_safe():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/auth/token"):
            return httpx.Response(403)
        return httpx.Response(200, json={})

    with pytest.raises(ScannerError, match="HTTP 403"):
        _http_scanner(handler).me()

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ScannerError, match="недоступен"):
        _http_scanner(boom).me()
