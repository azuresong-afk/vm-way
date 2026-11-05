"""Задача 2.5: исключения — принятие риска и ложные срабатывания, утверждающий, дата пересмотра,
продление и истечение, отметка ложных срабатываний в «Сканере»."""

from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app.integrations.scanner import MockScanner
from app.models import AuditLog, Comment, Outbox, Ticket, TicketException, Vulnerability
from app.services import exceptions as svc


@pytest.fixture()
def source_id(client, as_):
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    return src["id"]


@pytest.fixture()
def project(client, as_, source_id):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": source_id, "engagement_id": 7})
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    return pid


def _user(client, as_, username, roles):
    r = client.post(
        "/users", headers=as_("admin"), json={"username": username, "password": "long-enough-pw", "roles": roles}
    )
    assert r.status_code == 201, r.text
    tok = client.post("/auth/token", json={"username": username, "password": "long-enough-pw"}).json()
    return {"id": r.json()["id"], "h": {"Authorization": f"Bearer {tok['access_token']}"}}


@pytest.fixture()
def manager2(client, as_):
    return _user(client, as_, "ciso", ["manager"])


def _ticket(client, as_, pid, status="new"):
    rows = client.get(f"/projects/{pid}/tickets", headers=as_("viewer"), params={"limit": 500}).json()
    return next(t for t in rows if t["status"] == status)


def _soon(days=90) -> str:
    return (svc.today() + timedelta(days=days)).isoformat()


def _request(client, h, tid, **kw):
    body = {"kind": "risk_accepted", "reason": "Сервер выводится из эксплуатации в декабре", "review_on": _soon()}
    body.update(kw)
    return client.post(f"/tickets/{tid}/exceptions", headers=h, json=body)


def test_risk_acceptance_requested_by_engineer_approved_by_manager(client, as_, project, users, db):
    tid = _ticket(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/take", headers=as_("engineer"))
    meta = client.get(f"/projects/{project}/exception-meta", headers=as_("engineer")).json()
    assert [a["username"] for a in meta["approvers"]] == ["manager"] and meta["sync_available"] is False

    r = _request(
        client,
        as_("engineer"),
        tid,
        approver_id=users["manager"].id,
        measures="Порт закрыт на межсетевом экране, доступ только из сети администраторов",
    )
    assert r.status_code == 201, r.text
    ex = r.json()
    assert ex["status"] == "pending" and ex["kind_label"] == "Принятие риска"
    assert ex["approver"]["username"] == "manager" and ex["can"]["approve"] is False and ex["can"]["withdraw"]
    # Пока исключение ждёт утверждения, работа по заявке идёт как обычно.
    card = client.get(f"/tickets/{tid}", headers=as_("engineer")).json()
    assert card["status"] == "assigned" and card["can"]["exception"] is False
    assert card["exceptions"][0]["id"] == ex["id"]
    assert (
        client.post(f"/tickets/{tid}/status", headers=as_("engineer"), json={"status": "in_progress"}).status_code
        == 200
    )

    counts = client.get(f"/projects/{project}/exception-counts", headers=as_("manager")).json()
    assert counts["pending"] == 1 and counts["to_approve"] == 1 and counts["active"] == 0
    r = client.post(f"/exceptions/{ex['id']}/approve", headers=as_("manager"), json={"note": "Согласовано"})
    assert r.status_code == 200, r.text
    ex = r.json()
    assert ex["status"] == "active" and ex["decided_by"]["username"] == "manager" and ex["prev_status"] == "in_progress"
    assert ex["hosts"] and ex["vuln_count"] > 0 and ex["days_left"] == 90 and ex["review_soon"] is False
    t = db.get(Ticket, tid)
    db.refresh(t)
    assert t.status == "risk_accepted" and t.closed_at is not None
    body = db.scalars(select(Comment).where(Comment.ticket_id == tid, Comment.kind == "system")).all()[-1].body
    assert body.startswith("Принят риск до ") and "Порт закрыт" in body and "Утвердил: Manager" in body
    actions = [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert {"exception.request", "exception.approve"} <= set(actions)
    events = {o.type for o in db.scalars(select(Outbox))}
    assert {"vm.exception.requested", "vm.exception.approved", "vm.ticket.status_changed"} <= events
    rows = client.get(f"/projects/{project}/exceptions", headers=as_("viewer"), params={"state": "active"}).json()
    assert [x["id"] for x in rows] == [ex["id"]] and "can" in rows[0]
    rows = client.get(f"/projects/{project}/exceptions", headers=as_("viewer"), params={"q": f"№{tid}"}).json()
    assert [x["id"] for x in rows] == [ex["id"]]
    # Ручного возврата нет — только снятие исключения.
    r = client.post(f"/tickets/{tid}/status", headers=as_("manager"), json={"status": "assigned", "reason": "x"})
    assert r.status_code == 409 and "снимите исключение" in r.json()["detail"]


def test_request_validation(client, as_, project, users, manager2):
    tid = _ticket(client, as_, project)["id"]
    m = as_("manager")
    mid = users["manager"].id
    # Свободная заявка: исключение оформляет только руководитель.
    assert _request(client, as_("engineer"), tid, approver_id=mid).status_code == 403
    assert _request(client, as_("viewer"), tid, approver_id=mid).status_code == 403
    assert _request(client, m, tid, approver_id=manager2["id"], reason="коротко").status_code == 422
    assert _request(client, m, tid, approver_id=manager2["id"], review_on=None).status_code == 422
    past = (svc.today()).isoformat()
    assert _request(client, m, tid, approver_id=manager2["id"], review_on=past).status_code == 422
    assert _request(client, m, tid, approver_id=manager2["id"], review_on=_soon(366)).status_code == 422
    assert _request(client, m, tid, approver_id=mid).status_code == 422  # сам себе
    assert _request(client, m, tid, approver_id=users["engineer"].id).status_code == 422  # не может утверждать
    assert _request(client, m, tid, approver_id=None).status_code == 422
    # Ложное срабатывание — без даты пересмотра можно; отметка в «Сканере» выключена в источнике.
    r = _request(client, m, tid, kind="false_positive", approver_id=manager2["id"], review_on=None, sync_scanner=True)
    assert r.status_code == 422 and "настройках источника" in r.json()["detail"]
    assert (
        _request(client, m, tid, kind="false_positive", approver_id=manager2["id"], review_on=None).status_code == 201
    )
    # Второе открытое исключение по той же заявке — нельзя.
    assert _request(client, m, tid, approver_id=manager2["id"]).status_code == 409


def test_four_eyes_reject_and_withdraw(client, as_, project, users, manager2, db):
    tid = _ticket(client, as_, project)["id"]
    m = as_("manager")
    ex = _request(client, m, tid, approver_id=manager2["id"]).json()
    # Автор и посторонний не утверждают; отказ — в журнале.
    assert client.post(f"/exceptions/{ex['id']}/approve", headers=m).status_code == 403
    assert client.post(f"/exceptions/{ex['id']}/approve", headers=as_("engineer")).status_code == 403
    denied = db.scalars(select(AuditLog).where(AuditLog.action == "exception.denied")).all()
    assert len(denied) == 2 and denied[0].result == "denied" and denied[0].details["action"] == "approve"
    # Отклонение — с причиной; заявка не меняется.
    assert client.post(f"/exceptions/{ex['id']}/reject", headers=manager2["h"], json={"reason": ""}).status_code == 422
    r = client.post(f"/exceptions/{ex['id']}/reject", headers=manager2["h"], json={"reason": "Нужен план вывода"})
    assert r.json()["status"] == "rejected" and r.json()["decision_note"] == "Нужен план вывода"
    assert db.get(Ticket, tid).status == "new"
    assert client.post(f"/exceptions/{ex['id']}/approve", headers=manager2["h"]).status_code == 409
    # Новое — можно; автор отзывает.
    ex2 = _request(client, m, tid, approver_id=manager2["id"]).json()
    r = client.post(f"/exceptions/{ex2['id']}/withdraw", headers=m, json={"reason": "Передумали"})
    assert r.json()["status"] == "withdrawn"
    assert client.get(f"/projects/{project}/exception-counts", headers=m).json()["ended"] == 2


def test_revoke_returns_ticket_to_work(client, as_, project, users, manager2, db):
    t = _ticket(client, as_, project, status="no_vendor_fix")
    ex = _request(
        client, as_("manager"), t["id"], kind="false_positive", approver_id=manager2["id"], review_on=None
    ).json()
    client.post(f"/exceptions/{ex['id']}/approve", headers=manager2["h"])
    assert db.get(Ticket, t["id"]).status == "false_positive"
    assert (
        client.post(f"/exceptions/{ex['id']}/revoke", headers=as_("engineer"), json={"reason": "x"}).status_code == 403
    )
    assert client.post(f"/exceptions/{ex['id']}/revoke", headers=as_("manager"), json={"reason": ""}).status_code == 422
    r = client.post(
        f"/exceptions/{ex['id']}/revoke", headers=as_("manager"), json={"reason": "Пакет всё же используется"}
    )
    assert r.json()["status"] == "revoked" and r.json()["ended_by"]["username"] == "manager"
    t2 = db.get(Ticket, t["id"])
    db.refresh(t2)
    # Заявка из package_nofix возвращается в «Нет исправления у производителя».
    assert t2.status == "no_vendor_fix" and t2.closed_at is None
    assert client.get(f"/tickets/{t['id']}", headers=as_("manager")).json()["can"]["exception"] is True


def test_extend_and_expire(client, as_, project, users, manager2, db):
    tid = _ticket(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": users["engineer"].id})
    ex = _request(client, as_("engineer"), tid, approver_id=users["manager"].id, review_on=_soon(10)).json()
    client.post(f"/exceptions/{ex['id']}/approve", headers=as_("manager"))
    rows = client.get(f"/projects/{project}/exceptions", headers=as_("viewer"), params={"state": "review_soon"}).json()
    assert [x["id"] for x in rows] == [ex["id"]] and rows[0]["review_soon"] is True
    # Продлевает утверждающий, с причиной.
    url = f"/exceptions/{ex['id']}/extend"
    assert client.post(url, headers=as_("engineer"), json={"review_on": _soon(60), "reason": "ok"}).status_code == 403
    assert client.post(url, headers=manager2["h"], json={"review_on": _soon(60), "reason": ""}).status_code == 422
    r = client.post(url, headers=manager2["h"], json={"review_on": _soon(60), "reason": "Вывод перенесли на январь"})
    assert r.status_code == 200, r.text
    assert r.json()["days_left"] == 60 and r.json()["extensions"][0]["reason"] == "Вывод перенесли на январь"
    # До даты пересмотра ничего не истекает, после — заявка возвращается в работу.
    review = date.fromisoformat(_soon(60))
    assert svc.expire_due(db, on=review) == []
    db.commit()
    assert db.get(TicketException, ex["id"]).status == "active"
    svc.expire_due(db, on=review + timedelta(days=1))
    db.commit()
    e = db.get(TicketException, ex["id"])
    db.refresh(e)
    t = db.get(Ticket, tid)
    db.refresh(t)
    assert e.status == "expired" and e.ended_by is None and "дата пересмотра" in e.end_reason
    assert t.status == "assigned" and t.closed_at is None
    assert db.scalars(select(AuditLog).where(AuditLog.action == "exception.expire")).one().result == "ok"
    assert db.scalars(select(Outbox).where(Outbox.type == "vm.exception.expired")).one()


def test_false_positive_synced_to_scanner_and_unmarked(client, as_, project, users, manager2, source_id, db):
    mock = MockScanner.shared("demo")
    client.patch(f"/sources/{source_id}", headers=as_("admin"), json={"sync_false_positives": True})
    assert client.get(f"/projects/{project}/exception-meta", headers=as_("manager")).json()["sync_available"] is True
    tid = _ticket(client, as_, project)["id"]
    keys = {v.dedup_key for v in db.scalars(select(Vulnerability).where(Vulnerability.ticket_id == tid))}
    ex = _request(
        client,
        as_("manager"),
        tid,
        kind="false_positive",
        reason="Пакет установлен, но служба не запускается",
        approver_id=manager2["id"],
        review_on=None,
        sync_scanner=True,
    ).json()
    r = client.post(f"/exceptions/{ex['id']}/approve", headers=manager2["h"])
    assert r.status_code == 200
    ex = client.get(f"/exceptions/{ex['id']}", headers=as_("viewer")).json()
    assert ex["sync"]["state"] == "done" and ex["sync"]["done"] == len(keys) and set(ex["sync"]["marked"]) == keys
    marks = {k for (_, k) in mock.fp_marks}
    assert marks == keys
    assert next(iter(mock.fp_marks.values()))["reason"].startswith(f"«Устранение», заявка №{tid}: Пакет установлен")
    # «Сканер» больше не включает отмеченные находки в «Что исправить», а в находках они с отметкой.
    run_id = max(mock._runs)
    planned = {ref["id"] for fx in mock.client().fixes(run_id) for h in fx["hosts"] for ref in h["findings"]}
    fps = [f for f in mock.client().findings(run_id) if f["dedup_key"] in keys]
    assert fps and all(f["false_positive"] for f in fps) and not planned & {f["id"] for f in fps}
    # Снятие исключения снимает отметку в «Сканере».
    r = client.post(f"/exceptions/{ex['id']}/revoke", headers=as_("manager"), json={"reason": "Служба нужна"})
    assert r.status_code == 200
    ex = client.get(f"/exceptions/{ex['id']}", headers=as_("viewer")).json()
    assert ex["sync"]["action"] == "unmark" and ex["sync"]["state"] == "done" and ex["sync"]["marked"] == []
    assert mock.fp_marks == {}
    assert {"exception.sync"} <= {a.action for a in db.scalars(select(AuditLog))}


def test_false_positive_sync_without_scanner_rights_and_retry(client, as_, project, users, manager2, source_id, db):
    mock = MockScanner.shared("demo")
    mock.can_triage = False
    client.patch(f"/sources/{source_id}", headers=as_("admin"), json={"sync_false_positives": True})
    tid = _ticket(client, as_, project)["id"]
    ex = _request(
        client,
        as_("manager"),
        tid,
        kind="false_positive",
        approver_id=manager2["id"],
        review_on=None,
        sync_scanner=True,
    ).json()
    client.post(f"/exceptions/{ex['id']}/approve", headers=manager2["h"])
    ex = client.get(f"/exceptions/{ex['id']}", headers=as_("manager")).json()
    assert ex["sync"]["state"] == "failed" and "operator" in ex["sync"]["errors"][0]["error"]
    # Заявка всё равно в исключении: отметка в «Сканере» вторична.
    assert db.get(Ticket, tid).status == "false_positive"
    assert ex["can"]["sync"] is True
    assert client.post(f"/exceptions/{ex['id']}/sync", headers=as_("engineer")).status_code == 403
    mock.can_triage = True
    r = client.post(f"/exceptions/{ex['id']}/sync", headers=as_("manager"))
    assert r.status_code == 202, r.text
    ex = client.get(f"/exceptions/{ex['id']}", headers=as_("manager")).json()
    assert ex["sync"]["state"] == "done" and len(mock.fp_marks) == ex["sync"]["done"] > 0


def test_approve_refused_when_ticket_closed_meanwhile(client, as_, project, users, manager2, db):
    tid = _ticket(client, as_, project)["id"]
    ex = _request(client, as_("manager"), tid, approver_id=manager2["id"]).json()
    t = db.get(Ticket, tid)
    t.status = "verified"
    db.commit()
    r = client.post(f"/exceptions/{ex['id']}/approve", headers=manager2["h"])
    assert r.status_code == 409 and "уже закрыта" in r.json()["detail"]
