"""Задача 1.5: назначение, переходы статусов, переопределение, комментарии, история, массовые действия."""

import pytest
from sqlalchemy import select

from app.models import AuditLog, Outbox, Ticket, TicketHistory
from tests.conftest import login


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


@pytest.fixture()
def engineer2(client, as_):
    r = client.post(
        "/users", headers=as_("admin"), json={"username": "eng2", "password": "long-enough-pw", "roles": ["engineer"]}
    )
    assert r.status_code == 201
    u = r.json()
    r = client.post("/auth/token", json={"username": "eng2", "password": "long-enough-pw"})
    return {"id": u["id"], "h": {"Authorization": f"Bearer {r.json()['access_token']}"}}


def _tickets(client, as_, pid, **params):
    return client.get(f"/projects/{pid}/tickets", headers=as_("viewer"), params={"limit": 500, **params}).json()


def _one(client, as_, pid, status="new"):
    return next(t for t in _tickets(client, as_, pid) if t["status"] == status)


def _st(client, h, tid, status, reason=None):
    return client.post(f"/tickets/{tid}/status", headers=h, json={"status": status, "reason": reason})


def test_take_moves_new_to_assigned_and_subscribes(client, as_, project, users, db):
    t = _one(client, as_, project)
    r = client.post(f"/tickets/{t['id']}/take", headers=as_("engineer"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "assigned" and r.json()["assignee"]["username"] == "engineer"
    card = client.get(f"/tickets/{t['id']}", headers=as_("engineer")).json()
    assert card["watching"] is True
    assert card["can"]["statuses"] == ["in_progress", "waiting_window", "fixed"]
    assert card["can"]["take"] is False
    # «Мои задачи».
    mine = client.get(f"/projects/{project}/tickets", headers=as_("engineer"), params={"assignee": "me"}).json()
    assert [x["id"] for x in mine] == [t["id"]]
    hist = client.get(f"/tickets/{t['id']}/history", headers=as_("viewer")).json()["history"]
    assert [(h["action"], h["to"]) for h in hist][-2:] == [("assigned", "Engineer"), ("status", "assigned")]
    assert hist[-1]["actor"]["username"] == "engineer"
    a = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.take")).one()
    assert a.object_id == str(t["id"]) and a.project_id == project and a.username == "engineer"
    assert db.scalars(select(Outbox).where(Outbox.type == "vm.ticket.assigned")).one().data["assignee_id"]


def test_cannot_take_someone_elses_ticket(client, as_, project, engineer2):
    t = _one(client, as_, project)
    assert client.post(f"/tickets/{t['id']}/take", headers=as_("engineer")).status_code == 200
    r = client.post(f"/tickets/{t['id']}/take", headers=engineer2["h"])
    assert r.status_code == 409 and "уже назначена" in r.json()["detail"]
    # Повторное «Взять» своей заявки — ничего не меняет.
    assert client.post(f"/tickets/{t['id']}/take", headers=as_("engineer")).status_code == 200


def test_full_work_cycle(client, as_, project, users, db):
    tid = _one(client, as_, project)["id"]
    h = as_("engineer")
    # Из «Новая» в работу не взять: сначала назначение.
    r = _st(client, h, tid, "in_progress")
    assert r.status_code == 409 and "не разрешён" in r.json()["detail"]
    client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": users["engineer"].id})
    for to in ("in_progress", "waiting_window", "in_progress", "fixed"):
        r = _st(client, h, tid, to)
        assert r.status_code == 200, (to, r.text)
        assert r.json()["status"] == to
    # Из «Исправлено» обратно — только с причиной.
    assert _st(client, h, tid, "in_progress").status_code == 422
    assert _st(client, h, tid, "in_progress", "Не перезапустили службу").status_code == 200
    statuses = [
        (x.from_value, x.to_value)
        for x in db.scalars(
            select(TicketHistory).where(TicketHistory.ticket_id == tid, TicketHistory.action == "status")
        )
    ]
    assert statuses == [
        ("new", "assigned"),
        ("assigned", "in_progress"),
        ("in_progress", "waiting_window"),
        ("waiting_window", "in_progress"),
        ("in_progress", "fixed"),
        ("fixed", "in_progress"),
    ]
    # Каждый переход — в журнале аудита и событием.
    mine = select(AuditLog).where(AuditLog.action == "ticket.status", AuditLog.object_id == str(tid))
    assert len(db.scalars(mine).all()) == 5
    ours = select(Outbox).where(Outbox.type == "vm.ticket.status_changed", Outbox.subject == f"ticket/{tid}")
    assert len(db.scalars(ours).all()) == 5
    last = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.status").order_by(AuditLog.id.desc())).first()
    assert last.details["reason"] == "Не перезапустили службу"


@pytest.mark.parametrize("to", ["verified", "not_verified", "regression", "no_vendor_fix"])
def test_system_statuses_cannot_be_set_manually(client, as_, project, users, to):
    tid = _one(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": users["engineer"].id})
    _st(client, as_("engineer"), tid, "in_progress")
    _st(client, as_("engineer"), tid, "fixed")
    r = _st(client, as_("manager"), tid, to)
    assert r.status_code == 409 and "только система" in r.json()["detail"]


def test_invalid_transitions(client, as_, project, users):
    tid = _one(client, as_, project)["id"]
    m = as_("manager")
    assert _st(client, m, tid, "nonsense").status_code == 422
    assert _st(client, m, tid, "new").status_code == 409  # уже «Новая»
    # «Назначена» — только назначением.
    r = _st(client, m, tid, "assigned")
    assert r.status_code == 409 and "не разрешён" in r.json()["detail"]
    # Из «Новая» сразу в «Исправлено» — нельзя.
    assert _st(client, m, tid, "fixed").status_code == 409


def test_only_assignee_or_manager_moves_ticket(client, as_, project, users, engineer2, db):
    tid = _one(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": users["engineer"].id})
    r = _st(client, engineer2["h"], tid, "in_progress")
    assert r.status_code == 403
    denied = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.status", AuditLog.result == "denied")).one()
    assert denied.username == "eng2" and denied.details["to"] == "in_progress"
    assert _st(client, as_("manager"), tid, "in_progress").status_code == 200
    # Наблюдатель и администратор — не работают с заявками.
    assert _st(client, as_("viewer"), tid, "fixed").status_code == 403
    assert _st(client, as_("admin"), tid, "fixed").status_code == 403


def test_exceptions_by_manager_with_reason_and_reopen(client, as_, project, users, db):
    tid = _one(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/take", headers=as_("engineer"))
    # Исполнитель исключение не ставит.
    assert _st(client, as_("engineer"), tid, "risk_accepted", "Сервер выводится").status_code == 403
    assert _st(client, as_("manager"), tid, "risk_accepted").status_code == 422  # без причины
    r = _st(client, as_("manager"), tid, "risk_accepted", "Сервер выводится из эксплуатации в декабре")
    assert r.status_code == 200 and r.json()["closed_at"]
    # Закрытая заявка: не назначить, статус работы не поменять.
    assert client.post(f"/tickets/{tid}/assign", headers=as_("manager"), json={"assignee_id": None}).status_code == 409
    assert _st(client, as_("manager"), tid, "in_progress").status_code == 409
    card = client.get(f"/tickets/{tid}", headers=as_("manager")).json()
    assert card["can"]["statuses"] == ["assigned"]
    # Возврат из исключения — в «Назначена» (исполнитель остался), с причиной.
    assert _st(client, as_("manager"), tid, "assigned").status_code == 422
    r = _st(client, as_("manager"), tid, "assigned", "Вывод отложили")
    assert r.status_code == 200 and r.json()["closed_at"] is None


def test_no_vendor_fix_ticket(client, as_, project, users):
    t = _one(client, as_, project, status="no_vendor_fix")
    # Взять можно, статус не меняется: ждём исправления от производителя.
    r = client.post(f"/tickets/{t['id']}/take", headers=as_("engineer"))
    assert r.json()["status"] == "no_vendor_fix"
    assert _st(client, as_("engineer"), t["id"], "in_progress").status_code == 409
    _st(client, as_("manager"), t["id"], "false_positive", "Пакет не используется")
    r = _st(client, as_("manager"), t["id"], "no_vendor_fix", "Ошиблись")
    assert r.status_code == 200 and r.json()["status"] == "no_vendor_fix"


def test_assign_rules(client, as_, project, users):
    tid = _one(client, as_, project)["id"]
    m = as_("manager")
    # Только исполнитель или руководитель, активный.
    assert client.post(f"/tickets/{tid}/assign", headers=m, json={"assignee_id": users["viewer"].id}).status_code == 422
    assert client.post(f"/tickets/{tid}/assign", headers=m, json={"assignee_id": users["admin"].id}).status_code == 422
    assert client.post(f"/tickets/{tid}/assign", headers=m, json={"assignee_id": 9999}).status_code == 422
    # Исполнитель назначать не может.
    r = client.post(f"/tickets/{tid}/assign", headers=as_("engineer"), json={"assignee_id": users["engineer"].id})
    assert r.status_code == 403
    # Руководитель может назначить и себя.
    r = client.post(f"/tickets/{tid}/assign", headers=m, json={"assignee_id": users["manager"].id})
    assert r.json()["status"] == "assigned"
    _st(client, m, tid, "in_progress")
    # Снятие исполнителя возвращает заявку в «Новая».
    r = client.post(f"/tickets/{tid}/assign", headers=m, json={"assignee_id": None})
    assert r.json()["status"] == "new" and r.json()["assignee"] is None


def test_assignable_with_load(client, as_, project, users):
    tid = _one(client, as_, project)["id"]
    client.post(f"/tickets/{tid}/take", headers=as_("engineer"))
    rows = client.get("/users/assignable", headers=as_("viewer"), params={"project_id": project}).json()
    by = {r["username"]: r for r in rows}
    assert set(by) == {"engineer", "manager"}
    assert by["engineer"]["open_tickets"] == 1 and by["manager"]["open_tickets"] == 0


def test_override_with_reason(client, as_, project, db):
    t = _one(client, as_, project)
    tid = t["id"]
    sev = "low" if t["severity"] != "low" else "critical"
    body = {"severity": sev, "reason": ""}
    assert client.post(f"/tickets/{tid}/override", headers=as_("engineer"), json=body).status_code == 403
    assert client.post(f"/tickets/{tid}/override", headers=as_("manager"), json=body).status_code == 422
    body["reason"] = "Хост в DMZ, доступен из интернета"
    r = client.post(f"/tickets/{tid}/override", headers=as_("manager"), json=body)
    assert r.status_code == 200
    assert r.json()["severity"] == sev and r.json()["severity_overridden"] is True
    assert r.json()["scanner_severity"] == t["severity"]
    crit = _tickets(client, as_, project, severity=sev)
    assert tid in [x["id"] for x in crit]
    a = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.override")).one()
    assert a.details["before"]["severity"] == t["severity"] and a.details["after"]["severity"] == sev
    # Сброс к значению «Сканера» — тоже с причиной.
    r = client.post(
        f"/tickets/{tid}/override", headers=as_("manager"), json={"severity": None, "reason": "Хост убрали из DMZ"}
    )
    assert r.json()["severity"] == t["severity"] and r.json()["severity_overridden"] is False
    assert db.get(Ticket, tid).override_reason == ""
    assert (
        client.post(
            f"/tickets/{tid}/override", headers=as_("manager"), json={"severity": "bogus", "reason": "xxx"}
        ).status_code
        == 422
    )


def test_comments_and_watch(client, as_, project, users, db):
    tid = _one(client, as_, project)["id"]
    r = client.post(f"/tickets/{tid}/comments", headers=as_("engineer"), json={"body": "  Согласовал окно на пятницу "})
    assert r.status_code == 201 and r.json()["body"] == "Согласовал окно на пятницу"
    assert client.post(f"/tickets/{tid}/comments", headers=as_("engineer"), json={"body": "   "}).status_code == 422
    assert client.post(f"/tickets/{tid}/comments", headers=as_("viewer"), json={"body": "hi"}).status_code == 403
    comments = client.get(f"/tickets/{tid}/history", headers=as_("viewer")).json()["comments"]
    assert [(c["kind"], c["author"]["username"]) for c in comments] == [("user", "engineer")]
    a = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.comment")).one()
    assert a.details["length"] == len("Согласовал окно на пятницу")
    # Автор комментария — наблюдатель; наблюдатель-роль тоже может подписаться.
    assert client.post(f"/tickets/{tid}/watch", headers=as_("viewer")).json()["watching"] is True
    card = client.get(f"/tickets/{tid}", headers=as_("viewer")).json()
    assert {w["username"] for w in card["watchers"]} == {"engineer", "viewer"} and card["watching"]
    assert card["can"] == {
        "statuses": [],
        "take": False,
        "assign": False,
        "override": False,
        "comment": False,
        "verify": False,
        "window": False,
    }
    client.post(f"/tickets/{tid}/watch", headers=as_("viewer"), json={"watch": False})
    assert client.get(f"/tickets/{tid}", headers=as_("viewer")).json()["watching"] is False


def test_bulk_assign_and_status(client, as_, project, users, db):
    tickets = [t for t in _tickets(client, as_, project) if t["status"] == "new"][:4]
    nofix = _one(client, as_, project, status="no_vendor_fix")
    ids = [t["id"] for t in tickets]
    m = as_("manager")
    url = f"/projects/{project}/tickets/bulk"
    assert client.post(url, headers=as_("engineer"), json={"ticket_ids": ids, "action": "assign"}).status_code == 403
    r = client.post(url, headers=m, json={"ticket_ids": ids, "action": "assign", "assignee_id": users["engineer"].id})
    assert r.status_code == 200 and sorted(r.json()["changed"]) == sorted(ids) and r.json()["failed"] == []
    # Перевод: no_vendor_fix и чужой проект не проходят, остальные — да.
    other = client.post("/projects", headers=as_("admin"), json={"name": "Другой"}).json()["id"]
    r = client.post(
        f"/projects/{other}/tickets/bulk",
        headers=m,
        json={"ticket_ids": ids[:1], "action": "status", "status": "fixed"},
    )
    assert r.json()["failed"][0]["error"] == "Заявка не найдена в проекте"
    r = client.post(
        url, headers=m, json={"ticket_ids": [*ids, nofix["id"]], "action": "status", "status": "in_progress"}
    )
    body = r.json()
    assert sorted(body["changed"]) == sorted(ids)
    assert [f["id"] for f in body["failed"]] == [nofix["id"]]
    assert {t["status"] for t in _tickets(client, as_, project) if t["id"] in ids} == {"in_progress"}
    # Повторное назначение того же — без изменений.
    r = client.post(url, headers=m, json={"ticket_ids": ids, "action": "assign", "assignee_id": users["engineer"].id})
    assert r.json()["unchanged"] == ids
    bulk = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.bulk").order_by(AuditLog.id)).all()
    assert [b.result for b in bulk] == ["ok", "failed", "partial", "ok"]
    # Каждая заявка — своей записью.
    assert len(db.scalars(select(AuditLog).where(AuditLog.action == "ticket.assign")).all()) == 4
    assert client.post(url, headers=m, json={"ticket_ids": ids, "action": "status"}).status_code == 422


def test_role_revocation_blocks_work(client, as_, project, users):
    tid = _one(client, as_, project)["id"]
    h = login(client, "engineer")
    client.post(f"/tickets/{tid}/take", headers=h)
    client.patch(f"/users/{users['engineer'].id}", headers=as_("admin"), json={"roles": ["viewer"]})
    assert _st(client, h, tid, "in_progress").status_code == 403
