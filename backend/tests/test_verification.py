"""Задача 1.6: автозакрытие по импорту, регрессии и повторная проверка прицельным прогоном."""

import pytest
from sqlalchemy import func, select

from app.integrations.scanner import MockScanner
from app.models import (
    AuditLog,
    Comment,
    Outbox,
    ScanRun,
    Ticket,
    TicketHost,
    Verification,
    Vulnerability,
    VulnerabilityEvent,
)
from app.services import verification
from app.services.workflow import Actor

SSH_DEB = "Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3"
SSL_DEB = "Обновить libssl3 на Debian 12 до 3.0.14-1~deb12u2"
SSH_RED = "Обновить openssh на РЕД ОС 7.3 до 8.8p1-12.el7"
EXPAT = "Обновить libexpat1 на Debian 12 до 2.5.0-1+deb12u1"


@pytest.fixture()
def project(client, as_):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources",
        headers=as_("admin"),
        json={"name": "Сканер", "base_url": "mock://demo", "username": "svc", "web_url": "https://scanner.local/"},
    ).json()
    link = client.post(
        f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7}
    ).json()
    return {"id": pid, "link_id": link["id"]}


def _import(client, as_, pid, run_id=None):
    body = {"link_id": None, "scanner_run_id": run_id} if run_id else {}
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json=body).json()
    assert job["status"] == "done", job
    return job


def _ticket(db, title) -> Ticket:
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.title == title)).one()


def _hosts(t: Ticket) -> dict[str, str]:
    return {h.host: h.status for h in t.hosts}


def _start(client, as_, users, tid, **body):
    client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": users["engineer"].id})
    client.post(f"/tickets/{tid}/status", headers=as_("engineer"), json={"status": "in_progress"})
    return client.post(f"/tickets/{tid}/verify", headers=as_("engineer"), json=body)


# --- автозакрытие плановыми прогонами ---


def test_scheduled_runs_close_fixed_and_reopen_regressions(client, as_, db, project):
    pid = project["id"]
    _import(client, as_, pid, 100)
    _import(client, as_, pid, 101)
    # В октябре libexpat исправили на обоих хостах: заявка закрыта с доказательством.
    expat = _ticket(db, EXPAT)
    assert expat.status == "verified" and expat.closed_at is not None
    assert set(_hosts(expat).values()) == {"confirmed"}
    assert expat.evidence["scanner_run_id"] == 101
    assert expat.evidence["url"] == "https://scanner.local/runs/101"
    assert expat.evidence["run_name"] == "Плановый прогон — октябрь"
    fixed = db.scalars(select(Vulnerability).where(Vulnerability.ticket_id == expat.id)).all()
    assert {v.state for v in fixed} == {"fixed"}
    run101 = db.scalar(select(ScanRun).where(ScanRun.scanner_run_id == 101))
    assert {v.fixed_run_id for v in fixed} == {run101.id}
    assert run101.stats["vulns_fixed"] == 2 and run101.stats["tickets_verified"] == 1
    assert (
        db.scalar(
            select(Outbox).where(Outbox.type == "vm.remediation.verified", Outbox.subject == f"ticket/{expat.id}")
        )
        is not None
    )

    # В ноябре на 10.20.1.18 libexpat снова уязвим — регрессия, заявка открыта заново.
    _import(client, as_, pid, 102)
    expat = _ticket(db, EXPAT)
    assert expat.status == "regression" and expat.is_regression and expat.closed_at is None
    assert _hosts(expat) == {"10.20.1.17": "confirmed", "10.20.1.18": "open"}
    again = db.scalars(
        select(Vulnerability).where(Vulnerability.ticket_id == expat.id, Vulnerability.host == "10.20.1.18")
    ).one()
    assert again.state == "open" and again.is_regression and again.fixed_run_id is None
    events = db.scalars(select(VulnerabilityEvent.event).where(VulnerabilityEvent.vulnerability_id == again.id)).all()
    assert events == ["appeared", "fixed", "regression"]
    note = db.scalars(select(Comment).where(Comment.ticket_id == expat.id, Comment.kind == "system")).all()
    assert any("Регрессия" in c.body and "CVE-2024-45491" in c.body for c in note)

    # sudo (CVE-2023-28486) исправлен на всех 8 хостах — закрыт ноябрьским прогоном.
    sudo = db.scalars(select(Ticket).where(Ticket.title.like("Обновить sudo%"))).one()
    assert sudo.status == "verified" and sudo.evidence["scanner_run_id"] == 102

    # 10.20.3.36 в ноябре недоступен: его уязвимости не закрыты, хотя находок по нему нет.
    unreachable = db.scalars(select(Vulnerability).where(Vulnerability.host == "10.20.3.36")).all()
    assert unreachable and {v.state for v in unreachable} == {"open"}
    glibc = db.scalars(select(Ticket).where(Ticket.title.like("Обновить glibc%"))).one()
    assert glibc.status == "new" and _hosts(glibc)["10.20.3.31"] == "confirmed"
    ssh_red = _ticket(db, SSH_RED)
    assert ssh_red.status == "new" and _hosts(ssh_red)["10.20.3.36"] == "open"

    # Системные переводы — в журнале от имени «система».
    sys_rows = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.status", AuditLog.user_id.is_(None))).all()
    assert {(a.details["from"], a.details["to"]) for a in sys_rows} == {
        ("new", "verified"),
        ("verified", "regression"),
    }


def test_reimport_does_not_repeat_closure(client, as_, db, project):
    _import(client, as_, project["id"])
    n = db.scalar(select(func.count()).select_from(VulnerabilityEvent))
    _import(client, as_, project["id"])
    _import(client, as_, project["id"], 101)
    assert db.scalar(select(func.count()).select_from(VulnerabilityEvent)) == n


# --- повторная проверка ---


def test_verification_closes_fixed_ticket(client, as_, db, users, project):
    _import(client, as_, project["id"])
    t = _ticket(db, SSL_DEB)
    r = _start(client, as_, users, t.id)
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["ticket"]["status"] == "verified"
    [v] = out["verifications"]
    assert v["status"] == "done" and v["result"]["outcome"] == "verified"
    assert v["result"]["counts"] == {"confirmed": 6, "not_confirmed": 0, "unverified": 0}

    # Прицельный прогон: цели — хосты заявки, модули — нашедшие уязвимости + discovery, учётки — из прогона.
    mock = MockScanner.shared("demo")
    [(_, path, body)] = [x for x in mock.requests if x[0] == "POST" and x[1] == "/engagements/7/runs"]
    assert body["targets"] == [f"10.20.1.{i}" for i in range(11, 17)]
    assert body["modules"] == ["discovery", "auth_inventory"]
    assert body["credential_ids"] == [3]
    assert body["name"] == f"Проверка устранения: №{t.id} {SSL_DEB}"

    t = _ticket(db, SSL_DEB)
    run = db.scalar(select(ScanRun).where(ScanRun.kind == "verification"))
    assert run.scanner_run_id == v["scanner_run_id"] and v["run_id"] == run.id
    assert t.evidence["scanner_run_id"] == run.scanner_run_id and t.evidence["kind"] == "verification"
    assert {h.last_check_run_id for h in t.hosts} == {run.id}
    assert (
        db.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.ticket_id == t.id, Vulnerability.state == "open")
        )
        == 0
    )

    # Опрос не импортирует прицельный прогон второй раз.
    before = db.scalar(select(func.count()).select_from(ScanRun))
    _import(client, as_, project["id"])
    assert db.scalar(select(func.count()).select_from(ScanRun)) == before

    actions = db.scalars(select(AuditLog.action).where(AuditLog.object_id == str(t.id))).all()
    assert "ticket.verify" in actions and "ticket.verify_result" in actions
    card = client.get(f"/tickets/{t.id}", headers=as_("viewer")).json()
    assert card["status_label"] == "Подтверждено" and card["can"]["verify"] is False
    assert card["verifications"][0]["id"] == v["id"]
    assert client.get(f"/tickets/{t.id}/verifications", headers=as_("viewer")).json()[0]["id"] == v["id"]
    assert client.get(f"/verifications/{v['id']}", headers=as_("viewer")).json()["status"] == "done"


def test_verification_keeps_unfixed_and_marks_unchecked(client, as_, db, users, project):
    _import(client, as_, project["id"])
    t = _ticket(db, SSH_DEB)
    r = _start(client, as_, users, t.id)
    assert r.status_code == 202, r.text
    t = _ticket(db, SSH_DEB)
    # 11–15 обновили, 16 и 17 — нет, 18 недоступен.
    assert t.status == "not_verified" and t.closed_at is None
    hosts = {h.host: (h.status, h.reason) for h in t.hosts}
    for i in range(11, 16):
        assert hosts[f"10.20.1.{i}"] == ("confirmed", "")
    assert hosts["10.20.1.16"] == ("not_confirmed", "уязвимость осталась: CVE-2024-6387")
    assert hosts["10.20.1.17"][0] == "not_confirmed"
    assert hosts["10.20.1.18"] == ("unverified", "хост недоступен: хост не ответил на пробы обнаружения")
    [v] = r.json()["verifications"]
    assert v["result"]["outcome"] == "not_verified"
    assert v["result"]["counts"] == {"confirmed": 5, "not_confirmed": 2, "unverified": 1}
    vulns = {v_.host: v_ for v_ in db.scalars(select(Vulnerability).where(Vulnerability.ticket_id == t.id))}
    assert vulns["10.20.1.11"].state == "fixed" and vulns["10.20.1.16"].state == "open"
    assert vulns["10.20.1.18"].state == "open"
    ev = db.scalars(
        select(VulnerabilityEvent.event).where(VulnerabilityEvent.vulnerability_id == vulns["10.20.1.16"].id)
    )
    assert list(ev)[-1] == "still_present"
    comments = [c.body for c in db.scalars(select(Comment).where(Comment.ticket_id == t.id, Comment.kind == "system"))]
    assert any("не подтверждено" in c.lower() and "10.20.1.16" in c for c in comments)
    out = db.scalars(select(Outbox).where(Outbox.type == "vm.remediation.verified", Outbox.subject == f"ticket/{t.id}"))
    assert [o.data["result"] for o in out] == ["not_verified"]

    # Повторная проверка — только непроверенные и неподтверждённые хосты.
    client.post(f"/tickets/{t.id}/status", headers=as_("engineer"), json={"status": "in_progress"})
    r = client.post(f"/tickets/{t.id}/verify", headers=as_("engineer"), json={})
    assert r.status_code == 202, r.text
    posts = [x[2] for x in MockScanner.shared("demo").requests if x[0] == "POST" and x[1] == "/engagements/7/runs"]
    assert posts[-1]["targets"] == ["10.20.1.16", "10.20.1.17", "10.20.1.18"]


def test_partial_verification_keeps_ticket_waiting(client, as_, db, users, project):
    _import(client, as_, project["id"])
    t = _ticket(db, SSH_RED)
    r = _start(client, as_, users, t.id)
    assert r.status_code == 202, r.text
    t = _ticket(db, SSH_RED)
    hosts = _hosts(t)
    assert hosts.pop("10.20.3.36") == "unverified"
    assert set(hosts.values()) == {"confirmed"}
    # Неподтверждённых нет, но один хост не проверен — заявка ждёт проверки дальше.
    assert t.status == "fixed"
    assert r.json()["verifications"][0]["result"]["outcome"] == "partial"


def test_targets_outside_allowlist(client, as_, db, users, project):
    _import(client, as_, project["id"])
    mock = MockScanner.shared("demo")
    mock.data["allowlist"]["7"] = [{"id": 1, "cidr": "10.20.1.11/32"}]
    t = _ticket(db, SSL_DEB)
    r = _start(client, as_, users, t.id)
    assert r.status_code == 202, r.text
    t = _ticket(db, SSL_DEB)
    assert _hosts(t)["10.20.1.11"] == "confirmed"
    rest = [h for h in t.hosts if h.host != "10.20.1.11"]
    assert {h.status for h in rest} == {"unverified"}
    assert all(h.reason.startswith("вне allowlist «Сканера»") for h in rest)
    assert t.status == "fixed"
    v = r.json()["verifications"][0]
    assert len(v["denied_targets"]) == 5 and v["result"]["outcome"] == "partial"

    # Ни одной разрешённой цели: «Сканер» отвечает 422, прогона нет, всё «не проверено».
    mock.data["allowlist"]["7"] = [{"id": 1, "cidr": "10.99.0.0/24"}]
    t2 = _ticket(db, SSH_DEB)
    r = _start(client, as_, users, t2.id)
    assert r.status_code == 202, r.text
    v = r.json()["verifications"][0]
    assert v["status"] == "done" and v["scanner_run_id"] is None and v["result"]["outcome"] == "unverified"
    t2 = _ticket(db, SSH_DEB)
    # 10.20.1.11 закрыт ещё прошлой проверкой (единое правило: прогон закрывает всё, что проверил).
    hosts = _hosts(t2)
    assert hosts.pop("10.20.1.11") == "confirmed"
    assert set(hosts.values()) == {"unverified"} and t2.status == "fixed"


def test_verify_rules_and_rights(client, as_, db, users, project):
    _import(client, as_, project["id"])
    t = _ticket(db, SSH_DEB)
    assert client.post(f"/tickets/{t.id}/verify", headers=as_("viewer"), json={}).status_code == 403
    assert client.post(f"/tickets/{t.id}/verify", headers=as_("admin"), json={}).status_code == 403
    r = client.post(f"/tickets/{t.id}/verify", headers=as_("engineer"), json={"hosts": ["10.9.9.9"]})
    assert r.status_code == 422 and "10.9.9.9" in r.json()["detail"]
    # Новая заявка без исполнителя проверяется без смены статуса.
    r = client.post(f"/tickets/{t.id}/verify", headers=as_("engineer"), json={"hosts": ["10.20.1.11"]})
    assert r.status_code == 202, r.text
    t = _ticket(db, SSH_DEB)
    assert t.status == "new" and _hosts(t)["10.20.1.11"] == "confirmed"
    # Уже исправленный хост второй раз не проверяется.
    r = client.post(f"/tickets/{t.id}/verify", headers=as_("engineer"), json={"hosts": ["10.20.1.11"]})
    assert r.status_code == 409
    # Закрытую заявку не проверяют.
    ssl = _ticket(db, SSL_DEB)
    _start(client, as_, users, ssl.id)
    assert client.post(f"/tickets/{ssl.id}/verify", headers=as_("engineer"), json={}).status_code == 409
    # Пока идёт проверка — вторую не поставить.
    db.add(
        Verification(
            ticket_id=t.id, project_id=t.project_id, source_id=1, engagement_id=7, status="running", targets=[]
        )
    )
    db.commit()
    r = client.post(f"/tickets/{t.id}/verify", headers=as_("engineer"), json={})
    assert r.status_code == 409 and "уже идёт" in r.json()["detail"]


def test_restart_resumes_without_second_run(client, as_, db, users, project):
    _import(client, as_, project["id"])
    t = _ticket(db, SSL_DEB)
    [v] = verification.request(db, t, Actor(users["engineer"], {"verify", "ticket_work"}))
    db.commit()
    mock = MockScanner.shared("demo")
    mock.running_polls = 5

    def crash(_):
        raise RuntimeError("служба остановлена")

    with pytest.raises(RuntimeError):
        verification.execute(db, v.id, sleep=crash)
    db.expire_all()
    v = db.get(Verification, v.id)
    assert v.status == "running" and v.scanner_run_id is not None
    # После рестарта задача продолжает ждать тот же прогон.
    out = verification.execute(db, v.id, sleep=lambda _: None)
    assert out["status"] == "done" and out["result"]["outcome"] == "verified"
    posts = [x for x in mock.requests if x[0] == "POST" and x[1] == "/engagements/7/runs"]
    assert len(posts) == 1
    assert db.get(Ticket, t.id).status == "verified"
    assert db.scalar(select(func.count()).select_from(TicketHost).where(TicketHost.status == "confirmed")) >= 6
