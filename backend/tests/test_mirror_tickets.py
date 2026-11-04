"""Задача 1.4: зеркало уязвимостей по dedup_key и заявки из действий «Что исправить»."""

import copy

import pytest
from sqlalchemy import func, select

from app.integrations.scanner import MockScanner
from app.models import Comment, Outbox, Ticket, TicketHost, Vulnerability, VulnerabilityEvent


@pytest.fixture()
def project(client, as_):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    link = client.post(
        f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7}
    ).json()
    return {"id": pid, "link_id": link["id"]}


def _import(client, as_, pid, **body):
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json=body).json()
    assert job["status"] == "done", job
    return job


def _scanner_fix_keys() -> set[str]:
    mock = MockScanner.shared("demo")
    return {fx["key"] for r in mock.data["runs"] for fx in r["fixes"]}


def _scanner_dedup_keys() -> set[str]:
    mock = MockScanner.shared("demo")
    return {f["dedup_key"] for r in mock.data["runs"] for f in r["findings"]}


def test_one_ticket_per_fix_action(client, as_, db, project):
    _import(client, as_, project["id"])
    tickets = db.scalars(select(Ticket)).all()
    assert {t.fix_key for t in tickets} == _scanner_fix_keys()
    assert len(tickets) == 14
    # Подзадачи по хостам — как в действии «Сканера».
    ssh = next(t for t in tickets if t.title == "Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3")
    assert len(ssh.hosts) == 8 and {h.status for h in ssh.hosts} == {"open"}
    assert ssh.kind == "package" and ssh.os == "Debian 12" and ssh.severity == "high"
    assert ssh.action["commands"] == ["sudo apt-get update", "sudo apt-get install --only-upgrade -y openssh-server"]
    nofix = next(t for t in tickets if t.scanner_kind == "package_nofix")
    assert nofix.status == "no_vendor_fix"
    # Остальные — «Новая»; закрытие по плановым прогонам (sudo — «Подтверждено», libexpat — «Регрессия»)
    # проверяется в test_verification.py.
    by_status = {t.status for t in tickets if t.scanner_kind != "package_nofix"}
    assert by_status == {"new", "verified", "regression"}
    kernel = next(t for t in tickets if t.kind == "kernel" and t.os == "РЕД ОС 7.3")
    assert kernel.action["reboot"] is True


def test_mirror_by_dedup_key_and_reimport_has_no_duplicates(client, as_, db, project):
    _import(client, as_, project["id"])
    keys = _scanner_dedup_keys()
    assert {v.dedup_key for v in db.scalars(select(Vulnerability))} == keys
    counts = (
        db.scalar(select(func.count()).select_from(Vulnerability)),
        db.scalar(select(func.count()).select_from(Ticket)),
        db.scalar(select(func.count()).select_from(TicketHost)),
        db.scalar(select(func.count()).select_from(VulnerabilityEvent)),
    )
    # Повторно: по кнопке все новые и конкретный прогон — ничего не добавляется.
    _import(client, as_, project["id"])
    _import(client, as_, project["id"], link_id=project["link_id"], scanner_run_id=102)
    db.expire_all()
    assert counts == (
        db.scalar(select(func.count()).select_from(Vulnerability)),
        db.scalar(select(func.count()).select_from(Ticket)),
        db.scalar(select(func.count()).select_from(TicketHost)),
        db.scalar(select(func.count()).select_from(VulnerabilityEvent)),
    )
    assert db.scalar(select(func.count()).select_from(Outbox).where(Outbox.type == "vm.ticket.created")) == 14


def test_every_vulnerability_is_linked_to_its_ticket(client, as_, db, project):
    _import(client, as_, project["id"])
    vulns = db.scalars(select(Vulnerability)).all()
    assert all(v.ticket_id is not None for v in vulns)
    for v in vulns:
        t = db.get(Ticket, v.ticket_id)
        assert v.fix_key == t.fix_key and v.host in {h.host for h in t.hosts}
    # История: уязвимость впервые появилась в первом прогоне, где её нашли.
    ssh = next(v for v in vulns if v.host == "10.20.1.11" and v.software == "OpenSSH")
    ev = db.scalars(select(VulnerabilityEvent).where(VulnerabilityEvent.vulnerability_id == ssh.id)).all()
    assert [e.event for e in ev] == ["appeared"]


def test_new_hosts_extend_existing_ticket(client, as_, db, project):
    # Сначала только сентябрь, потом ноябрь: в заявку libxml2 (появилась в ноябре) — новая заявка,
    # а в существующие заявки хосты не дублируются.
    _import(client, as_, project["id"], link_id=project["link_id"], scanner_run_id=100)
    assert db.scalar(select(func.count()).select_from(Ticket)) == 13
    _import(client, as_, project["id"], link_id=project["link_id"], scanner_run_id=102)
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Ticket)) == 14
    hosts = db.execute(select(TicketHost.ticket_id, TicketHost.host)).all()
    assert len(hosts) == len(set(hosts))


def test_vendor_fix_appears_for_nofix_ticket(client, as_, db, project):
    _import(client, as_, project["id"])
    mock = MockScanner.shared("demo")
    run = copy.deepcopy(mock._runs[102])
    run["run"].update(id=103, name="Плановый прогон — декабрь", finished_at="2026-12-01T21:00:00Z")
    fx = next(f for f in run["fixes"] if f["kind"] == "package_nofix")
    fx.update(
        kind="package",
        key="libtiff-fixed-key",
        fixed_version="4.1.0+git191117-2~deb10u9",
        title="Обновить libtiff5 до 4.1.0+git191117-2~deb10u9",
    )
    mock._runs[103] = run
    _import(client, as_, project["id"])
    db.expire_all()
    old = db.scalar(select(Ticket).where(Ticket.scanner_kind == "package_nofix"))
    new = db.scalar(select(Ticket).where(Ticket.fix_key == "libtiff-fixed-key"))
    assert new.status == "new" and new.title == "Обновить libtiff5 на Astra Linux 1.7 до 4.1.0+git191117-2~deb10u9"
    assert {v.ticket_id for v in db.scalars(select(Vulnerability).where(Vulnerability.software == "LibTIFF"))} == {
        new.id
    }
    note = db.scalar(select(Comment).where(Comment.ticket_id == old.id, Comment.kind == "system"))
    assert "Производитель выпустил исправление" in note.body and f"№{new.id}" in note.body


# --- API ---


def test_tickets_api_filters_and_sort(client, as_, project):
    _import(client, as_, project["id"])
    h = as_("viewer")
    url = f"/projects/{project['id']}/tickets"
    r = client.get(url, headers=h)
    assert r.headers["X-Total-Count"] == "14"
    first = r.json()[0]
    assert first["priority"]["rank"] == min(t["priority"]["rank"] for t in r.json())
    deb = client.get(url, headers=h, params={"os": "Debian 12"}).json()
    assert {t["os"] for t in deb} == {"Debian 12"} and len(deb) == 5
    crit = client.get(url, headers=h, params={"severity": ["critical"]}).json()
    assert crit and {t["severity"] for t in crit} == {"critical"}
    kern = client.get(url, headers=h, params={"kind": "kernel"}).json()
    assert len(kern) == 2 and all(t["reboot"] for t in kern)
    by_cve = client.get(url, headers=h, params={"q": "CVE-2024-6387"}).json()
    assert [t["title"] for t in by_cve] == ["Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3"]
    by_host = client.get(url, headers=h, params={"host": "10.20.3.36"}).json()
    assert by_host and all(t["os"] in ("РЕД ОС 7.3",) for t in by_host)
    assert client.get(url, headers=h, params={"assignee": "none"}).headers["X-Total-Count"] == "14"
    assert client.get(url, headers=h, params={"assignee": "me"}).json() == []
    closed = client.get(url, headers=h, params={"state": "closed"}).json()
    assert [(t["status"], t["cves"]) for t in closed] == [("verified", ["CVE-2023-28486"])]
    page = client.get(url, headers=h, params={"limit": 5, "offset": 10})
    assert len(page.json()) == 4 and page.headers["X-Total-Count"] == "14"
    by_num = client.get(url, headers=h, params={"q": f"№{first['id']}"}).json()
    assert [t["id"] for t in by_num] == [first["id"]]


def test_ticket_card(client, as_, project):
    _import(client, as_, project["id"])
    h = as_("viewer")
    tid = client.get(f"/projects/{project['id']}/tickets", headers=h, params={"q": "CVE-2024-6387"}).json()[0]["id"]
    t = client.get(f"/tickets/{tid}", headers=h).json()
    assert t["hosts_total"] == 8 and t["vulns_open"] == 8
    assert {h_["host"] for h_ in t["hosts"]} == {f"10.20.1.{i}" for i in range(11, 19)}
    assert all(len(h_["vulnerability_ids"]) == 1 for h_ in t["hosts"])
    assert t["action"]["advisories"] == ["DSA-5724-1"] and t["status_label"] == "Новая"
    assert t["vulnerabilities"][0]["bdu_ids"] == ["BDU:2024-04835"]
    hist = client.get(f"/tickets/{tid}/history", headers=h).json()
    assert [x["action"] for x in hist["history"]] == ["created"]
    assert client.get("/tickets/999999", headers=h).status_code == 404


def test_vulnerabilities_api(client, as_, project):
    _import(client, as_, project["id"])
    h = as_("viewer")
    r = client.get(f"/projects/{project['id']}/vulnerabilities", headers=h, params={"host": "10.20.1.11"})
    assert int(r.headers["X-Total-Count"]) == len(r.json()) > 0
    assert r.json()[0]["severity"] == "critical"
    v = client.get(f"/vulnerabilities/{r.json()[0]['id']}", headers=h).json()
    assert v["events"][0]["event"] == "appeared" and v["events"][0]["scanner_run_id"] == 100
    meta = client.get("/ticket-meta", headers=h).json()
    assert {s["id"] for s in meta["statuses"]} >= {"new", "verified", "regression", "no_vendor_fix"}


def test_other_project_is_isolated(client, as_, project):
    _import(client, as_, project["id"])
    other = client.post("/projects", headers=as_("admin"), json={"name": "Другой"}).json()["id"]
    assert client.get(f"/projects/{other}/tickets", headers=as_("viewer")).json() == []
