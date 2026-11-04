"""Адаптер «Сканера»: мок на фикстуре и HTTP-клиент на подменённом транспорте."""

import hashlib
import json

import httpx
import pytest

from app.integrations.scanner import FINISHED_STATUSES, HttpScannerClient, MockScanner, ScannerError, make_client
from app.integrations.scanner.client import normalize_coverage


@pytest.fixture()
def mock():
    m = MockScanner()
    m.running_polls = 0
    return m


def test_fixture_shape(mock):
    hosts = mock.data["hosts"]
    assert len(hosts) == 20
    assert len({h["os_family"] for h in hosts}) == 3
    runs = mock.runs(7)
    assert [r["id"] for r in runs] == [102, 101, 100]
    assert all(r["status"] in FINISHED_STATUSES for r in runs)


def test_dedup_key_is_stable_between_runs(mock):
    keys = {r: {f["dedup_key"] for f in mock.findings(r)} for r in (100, 101, 102)}
    # Уязвимость openssh на web-01 — одна и та же во всех трёх прогонах.
    f = next(x for x in mock.findings(100) if x["host"] == "10.20.1.11" and x["software"] == "openssh-server")
    assert (
        f["dedup_key"] == hashlib.sha256(f"{f['host']}|{f['port']}|{f['vuln_id']}|{f['module']}".encode()).hexdigest()
    )
    assert all(f["dedup_key"] in keys[r] for r in (100, 101, 102))


def test_fixes_reference_findings(mock):
    ids = {f["id"] for f in mock.findings(102)}
    fixes = mock.fixes(102)
    assert {fx["os_family"] for fx in fixes if fx["os_family"]} == {"debian", "astra", "redos"}
    for fx in fixes:
        assert fx["host_count"] == len(fx["hosts"])
        for h in fx["hosts"]:
            assert {ref["id"] for ref in h["findings"]} <= ids


def test_unreachable_host_in_coverage(mock):
    cov = mock.coverage(102)
    srv06 = [c for c in cov if c["host"] == "10.20.3.36"]
    assert srv06 and all(c["status"] == "unreachable" for c in srv06)
    assert not [f for f in mock.findings(102) if f["host"] == "10.20.3.36"]


def test_targeted_run(mock):
    ssh = next(fx for fx in mock.fixes(102) if fx["packages"] == ["openssh-server"] and fx["os_family"] == "debian")
    targets = [h["host"] for h in ssh["hosts"]] + ["192.168.99.1"]
    started = mock.start_run(7, {"targets": targets, "modules": ["auth_inventory"], "name": "Проверка устранения: №1"})
    assert started["denied_targets"] == ["192.168.99.1"]
    assert started["status"] == "running"
    run = mock.run(started["id"])
    assert run["status"] == "done"
    left = {f["host"] for f in mock.findings(run["id"]) if f["software"] == "openssh-server"}
    # Исправлены web-01..04 и app-01; app-02 и db-01 — нет; mon-01 недоступен.
    assert left == {"10.20.1.16", "10.20.1.17"}
    cov = {c["host"]: c["status"] for c in mock.coverage(run["id"])}
    assert cov["10.20.1.18"] == "unreachable" and cov["10.20.1.11"] == "completed"


def test_targeted_run_no_credentials(mock):
    started = mock.start_run(7, {"targets": ["10.20.2.26"], "modules": ["auth_inventory"]})
    assert mock.coverage(started["id"])[0]["status"] == "no_credentials"
    assert mock.findings(started["id"]) == []


def test_targeted_run_all_denied(mock):
    with pytest.raises(ScannerError):
        mock.start_run(7, {"targets": ["8.8.8.8"], "modules": ["vuln"]})


def test_make_client():
    assert isinstance(make_client("mock://demo"), MockScanner)
    assert make_client("mock://demo") is make_client("mock://demo")
    with pytest.raises(ScannerError):
        make_client("ftp://x")


def test_normalize_coverage_nested():
    data = {
        "hosts": [
            {"host": "h1", "modules": {"vuln": "completed", "auth_inventory": {"status": "timeout", "reason": "SSH"}}}
        ]
    }
    assert normalize_coverage(data) == [
        {"host": "h1", "module": "vuln", "status": "completed", "reason": ""},
        {"host": "h1", "module": "auth_inventory", "status": "timeout", "reason": "SSH"},
    ]


def _http_scanner(handler):
    c = HttpScannerClient("https://scanner.local/api", "svc", "pw", transport=httpx.MockTransport(handler))
    c.retry_delay = 0
    return c


def test_http_login_pagination_and_reauth():
    state = {"logins": 0, "expired_once": False}
    items = [{"id": i} for i in range(1200)]

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
        return httpx.Response(200, json=items[off : off + lim], headers={"X-Total-Count": str(len(items))})

    c = _http_scanner(handler)
    assert len(c.findings(5)) == 1200
    assert state["logins"] == 2  # повторный вход после 401


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


def test_http_start_run_posts_body():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t"})
        seen["path"], seen["body"] = req.url.path, json.loads(req.content)
        return httpx.Response(201, json={"id": 9, "accepted_targets": ["10.0.0.1"], "denied_targets": []})

    r = _http_scanner(handler).start_run(7, {"targets": ["10.0.0.1"], "modules": ["auth_inventory"]})
    assert r["id"] == 9 and seen["path"] == "/api/engagements/7/runs" and seen["body"]["modules"] == ["auth_inventory"]
