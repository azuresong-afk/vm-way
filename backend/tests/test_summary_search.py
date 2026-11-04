"""Задача 1.7: сводка проекта и быстрый поиск."""

import pytest


@pytest.fixture()
def project(client, as_):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    return pid


def test_summary_counts_match_lists(client, as_, project):
    h = as_("viewer")
    s = client.get(f"/projects/{project}/summary", headers=h).json()
    open_tickets = client.get(f"/projects/{project}/tickets", headers=h, params={"state": "open", "limit": 1})
    open_vulns = client.get(f"/projects/{project}/vulnerabilities", headers=h, params={"state": "open", "limit": 1})
    assert s["open_tickets"] == int(open_tickets.headers["X-Total-Count"]) > 0
    assert s["open_vulns"] == int(open_vulns.headers["X-Total-Count"]) > 0
    assert sum(s["vulns_by_severity"].values()) == s["open_vulns"]
    assert sum(s["tickets_by_severity"].values()) == s["open_tickets"]
    assert s["by_status"]["verified"] == len(s["recent_verified"]) >= 1
    assert s["recent_verified"][0]["evidence"]["scanner_run_id"]
    # Недели: 13 за три месяца, сумма по неделям = «появилось» и «закрыто» за период.
    assert len(s["weeks"]) == 13
    assert sum(sum(w["opened"].values()) for w in s["weeks"]) == s["opened"]
    assert sum(sum(w["closed"].values()) for w in s["weeks"]) == s["closed"] > 0
    assert s["delta"] == s["open_vulns"] - s["open_vulns_at_start"]
    assert [m["severity"] for m in s["mttr"]] == ["critical", "high", "medium", "low", "info"]
    assert any(m["days"] for m in s["mttr"])
    top = s["top_hosts"]
    assert top and top[0]["open"] == sum(top[0]["by_severity"].values())
    assert s["last_run"]["kind"] == "scheduled"


def test_summary_year_and_validation(client, as_, project):
    h = as_("viewer")
    assert len(client.get(f"/projects/{project}/summary", headers=h, params={"period": "1y"}).json()["weeks"]) == 52
    assert client.get(f"/projects/{project}/summary", headers=h, params={"period": "5y"}).status_code == 422
    assert client.get("/projects/nope/summary", headers=h).status_code == 404
    assert client.get(f"/projects/{project}/summary").status_code == 401


def test_search_tickets_hosts_and_vulns(client, as_, project):
    h = as_("viewer")
    tickets = client.get(f"/projects/{project}/tickets", headers=h, params={"limit": 500}).json()
    t = tickets[0]
    r = client.get("/search", headers=h, params={"q": f"№{t['id']}", "project": project}).json()
    assert r["tickets"][0]["id"] == t["id"]
    assert r["tickets"][0]["url"] == f"/tickets/{t['id']}?project={project}"

    host = client.get(f"/tickets/{t['id']}", headers=h).json()["hosts"][0]["host"]
    r = client.get("/search", headers=h, params={"q": host, "project": project}).json()
    assert any(x["host"] == host for x in r["hosts"])

    cve = t["cves"][0]
    r = client.get("/search", headers=h, params={"q": cve}).json()
    assert r["vulns"][0]["id"] == cve and r["vulns"][0]["host_count"] >= 1
    assert r["counts"]["vulns"] >= 1

    assert client.get("/search", headers=h, params={"q": "  "}).status_code == 422
    assert client.get("/search", headers=h, params={"q": "x", "project": "nope"}).status_code == 404


def test_ticket_facets(client, as_, project):
    h = as_("viewer")
    f = client.get(f"/projects/{project}/ticket-facets", headers=h).json()
    tickets = client.get(f"/projects/{project}/tickets", headers=h, params={"limit": 500}).json()
    assert {o["id"] for o in f["os"]} == {t["os"] for t in tickets if t["os"]}
    assert sum(k["total"] for k in f["kinds"]) == len(tickets)
    assert all(0 <= k["open"] <= k["total"] for k in f["kinds"])
