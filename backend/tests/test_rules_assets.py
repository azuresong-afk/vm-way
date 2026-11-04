"""Задача 2.2: активы и группы «Сканера», команды и правила назначения по загрузке."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.integrations.scanner import MockScanner
from app.models import (
    Asset,
    AssetGroup,
    AssignmentRule,
    AuditLog,
    Outbox,
    ScanRun,
    Ticket,
    TicketHistory,
    TicketHost,
)
from app.services import rules, windows

TLS = "Настроить: Разрешены устаревшие протоколы TLS 1.0 и TLS 1.1"
TOMCAT = "Обновить Apache Tomcat"
LIBSSL = "Обновить libssl3 на Debian 12 до 3.0.14-1~deb12u2"
BIND = "Обновить bind9 на Astra Linux 1.7 до 1:9.11.5.P4+dfsg-5.1+deb10u11+ci1"
GLIBC = "Обновить glibc на РЕД ОС 7.3 до 2.35-9.el7"
SSH_DEB = "Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3"
DMZ = [f"10.20.1.{i}" for i in range(11, 15)]


@pytest.fixture()
def linked(client, as_):
    """Проект, привязанный к «Сканеру», без импорта."""
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    r = client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    assert r.status_code == 201, r.text
    return pid


def _import(client, as_, pid, run_id=100):
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={"scanner_run_id": run_id}).json()
    assert job["status"] == "done", job
    return job


def _engineers(client, as_, *names) -> list[int]:
    out = []
    for n in names:
        r = client.post(
            "/users",
            headers=as_("admin"),
            json={"username": n, "display_name": n.title(), "password": "correct-horse-battery", "roles": ["engineer"]},
        )
        assert r.status_code == 201, r.text
        out.append(r.json()["id"])
    return out


def _rule(client, as_, pid, **kw) -> dict:
    r = client.post(f"/projects/{pid}/rules", headers=as_("manager"), json={"name": "Правило", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def _ticket(db, title) -> Ticket:
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.title == title)).one()


# --- активы ---


def test_assets_synced_on_import_and_shown_in_ticket(client, as_, linked, db):
    _import(client, as_, linked)
    rows = client.get(f"/projects/{linked}/assets", headers=as_("viewer"), params={"limit": 100})
    assert rows.status_code == 200 and rows.headers["X-Total-Count"] == "20"
    db01 = next(a for a in rows.json() if a["hostname"] == "db-01")
    assert db01["criticality"] == "critical" and db01["groups"] == ["Базы данных"]
    assert db01["tags"] == ["pdn", "prod"] and db01["owner"] == "Группа СУБД" and db01["open_tickets"] > 0
    f = client.get(f"/projects/{linked}/asset-facets", headers=as_("viewer")).json()
    groups = {g["name"]: g for g in f["groups"]}
    assert groups["Резерв"] == {"name": "Резерв", "assets": 0, "open_tickets": 0}
    assert groups["DMZ"]["assets"] == 4 and groups["DMZ"]["open_tickets"] > 0
    assert f["criticality"]["critical"] == 3 and {"pdn", "prod"} <= {t["name"] for t in f["tags"]}
    # Фильтры списка.
    dmz = client.get(f"/projects/{linked}/assets", headers=as_("viewer"), params={"group": "DMZ"}).json()
    assert sorted(a["address"] for a in dmz) == DMZ
    pdn = client.get(f"/projects/{linked}/assets", headers=as_("viewer"), params={"tag": "PDN"})
    assert {a["hostname"] for a in pdn.json()} == {"db-01", "srv-01"} and pdn.headers["X-Total-Count"] == "2"
    # В карточке заявки — актив по каждому хосту; srv-06 без группы и владельца.
    t = _ticket(db, SSH_DEB)
    card = client.get(f"/tickets/{t.id}", headers=as_("viewer")).json()
    web = next(h for h in card["hosts"] if h["host"] == DMZ[0])
    assert web["asset"]["hostname"] == "web-01" and web["asset"]["groups"] == ["DMZ"]
    run = db.scalars(select(ScanRun)).one()
    assert run.stats["assets"] == 20


def test_sync_button_updates_removes_and_drops_groups(client, as_, linked, db):
    _import(client, as_, linked)
    mock = MockScanner.shared("demo")
    assets = mock.data["assets"]["7"]
    gone = assets.pop()  # srv-06 удалён в «Сканере»
    assets[0]["owner"] = "Новый владелец"
    mock.data["asset_groups"]["7"] = [g for g in mock.data["asset_groups"]["7"] if g["name"] != "Резерв"]
    assert client.post(f"/projects/{linked}/assets/sync", headers=as_("viewer")).status_code == 403
    r = client.post(f"/projects/{linked}/assets/sync", headers=as_("engineer"))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["removed"] == 1 and out["assets"] == 19 and out["groups_removed"] == 1 and not out["errors"]
    db.expire_all()
    assert db.scalar(select(Asset).where(Asset.address == gone["address"])) is None
    assert db.scalar(select(Asset).where(Asset.address == assets[0]["address"])).owner == "Новый владелец"
    assert "Резерв" not in set(db.scalars(select(AssetGroup.name)))
    log = db.scalars(select(AuditLog).where(AuditLog.action == "assets.sync")).one()
    assert log.username == "engineer" and log.details["removed"] == 1


def test_sync_without_link_and_import_survives_asset_error(client, as_, linked, db, monkeypatch):
    lonely = client.post("/projects", headers=as_("admin"), json={"name": "Без привязки"}).json()["id"]
    assert client.post(f"/projects/{lonely}/assets/sync", headers=as_("manager")).status_code == 409

    def broken(self, eid):
        raise LookupError("assets are not available")

    monkeypatch.setattr(MockScanner, "_assets", broken)
    _import(client, as_, linked)
    run = db.scalars(select(ScanRun)).one()
    assert "assets_error" in run.stats and run.stats["fixes"] > 0
    assert db.scalar(select(Ticket.id).limit(1)) is not None
    assert client.post(f"/projects/{linked}/assets/sync", headers=as_("manager")).status_code == 502


# --- правила ---


def test_rules_auto_assign_new_tickets_on_import(client, as_, linked, users, db):
    e2, e3 = _engineers(client, as_, "anna", "boris")
    team = client.post("/teams", headers=as_("manager"), json={"name": "Веб-сервисы", "member_ids": [e2, e3]})
    assert team.status_code == 201, team.text
    team = team.json()
    r1 = _rule(client, as_, linked, name="DMZ и приложения", groups=["DMZ", "Серверы приложений"], team_id=team["id"])
    r2 = _rule(client, as_, linked, name="Инфраструктура", groups=["Инфраструктура"], assignee_id=users["engineer"].id)
    r3 = _rule(client, as_, linked, name="РЕД ОС", os=["РЕД ОС 7.3"], assignee_id=users["manager"].id)
    assert [r1["position"], r2["position"], r3["position"]] == [1, 2, 3]
    _import(client, as_, linked)
    db.expire_all()
    # glibc на РЕД ОС стоит только на srv-01…04 — все они «Серверы приложений»: правило 1 раньше правила 3.
    web = [_ticket(db, t) for t in (TLS, TOMCAT, LIBSSL, GLIBC)]
    assert {t.status for t in web} == {"assigned"}
    load = [sum(1 for t in web if t.assignee_id == u) for u in (e2, e3)]
    assert load == [2, 2], "команда распределяет по загрузке"
    assert _ticket(db, BIND).assignee_id == users["engineer"].id
    # Остальные заявки РЕД ОС задевают srv-06 без группы — срабатывает правило по ОС.
    red = db.scalars(
        select(Ticket).where(Ticket.os == "РЕД ОС 7.3", Ticket.status != "no_vendor_fix", Ticket.title != GLIBC)
    ).all()
    assert len(red) == 2 and {t.assignee_id for t in red} == {users["manager"].id}
    # Смешанная заявка (хосты разных групп) по правилу «все хосты» не назначается.
    ssh = _ticket(db, SSH_DEB)
    assert ssh.status == "new" and ssh.assignee_id is None
    # История, журнал и outbox — как у ручного назначения, от имени системы.
    h = db.scalars(
        select(TicketHistory).where(TicketHistory.ticket_id == web[0].id, TicketHistory.action == "assigned")
    )
    h = h.one()
    assert h.actor_id is None and h.details["via"] == "rule" and h.details["rule_id"] == r1["id"]
    assert h.details["team"] == "Веб-сервисы"
    logs = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.assign")).all()
    assert logs and all(lg.username == "система" for lg in logs)
    apply_log = db.scalars(select(AuditLog).where(AuditLog.action == "rules.apply")).one()
    assert apply_log.details["auto"] is True and apply_log.details["assigned"] == len(logs)
    assert db.scalars(select(Outbox).where(Outbox.type == "vm.ticket.assigned")).all()
    run = db.scalars(select(ScanRun)).one()
    assert run.stats["tickets_auto_assigned"] == len(logs)
    # Повторный импорт тех же заявок не трогает: правила — только для созданных.
    client.post(f"/tickets/{ssh.id}/take", headers=as_("engineer"))
    client.post(f"/tickets/{ssh.id}/assign", headers=as_("manager"), json={"assignee_id": None})
    _import(client, as_, linked, 101)
    assert _ticket(db, SSH_DEB).assignee_id is None


def test_apply_with_preview_and_host_match_any(client, as_, linked, users, db):
    _import(client, as_, linked)
    rule = _rule(
        client, as_, linked, name="Есть БД", groups=["Базы данных"], host_match="any", assignee_id=users["manager"].id
    )
    before = db.scalar(select(Ticket.id).where(Ticket.assignee_id.is_not(None)))
    assert before is None
    prev = client.post(f"/projects/{linked}/rules/apply", headers=as_("manager"), json={"dry_run": True}).json()
    hit = [i for i in prev["items"] if i["rule"]]
    assert prev["dry_run"] and hit and prev["assigned"] == len(hit)
    assert {i["title"] for i in hit} >= {SSH_DEB} and all(i["rule"]["id"] == rule["id"] for i in hit)
    miss = next(i for i in prev["items"] if i["title"] == TLS)
    assert miss["rule"] is None and miss["note"] == "ни одно правило не подошло"
    db.expire_all()
    assert db.scalar(select(Ticket.id).where(Ticket.assignee_id.is_not(None))) is None, "предпросмотр ничего не меняет"
    assert client.post(f"/projects/{linked}/rules/apply", headers=as_("engineer"), json={}).status_code == 403
    done = client.post(f"/projects/{linked}/rules/apply", headers=as_("manager"), json={"dry_run": False}).json()
    assert done["assigned"] == len(hit)
    assert _ticket(db, SSH_DEB).assignee_id == users["manager"].id
    log = db.scalars(select(AuditLog).where(AuditLog.action == "rules.apply")).one()
    assert log.username == "manager" and log.details["auto"] is False
    again = client.post(f"/projects/{linked}/rules/apply", headers=as_("manager"), json={"dry_run": False}).json()
    assert again["assigned"] == 0


def test_rule_without_available_target_falls_through(client, as_, linked, users, db):
    (e2,) = _engineers(client, as_, "anna")
    team = client.post("/teams", headers=as_("manager"), json={"name": "Ночная смена", "member_ids": [e2]}).json()
    _rule(client, as_, linked, name="Команда", kinds=["config"], team_id=team["id"])
    _rule(client, as_, linked, name="Запасное", kinds=["config"], assignee_id=users["engineer"].id)
    client.patch(f"/users/{e2}", headers=as_("admin"), json={"is_active": False})
    _import(client, as_, linked)
    assert _ticket(db, TLS).assignee_id == users["engineer"].id
    listed = client.get("/teams", headers=as_("viewer")).json()[0]
    assert listed["members"][0]["available"] is False and listed["rules"] == 1
    # Некому назначить ни по одному правилу — причина в предпросмотре.
    client.patch(f"/users/{users['engineer'].id}", headers=as_("admin"), json={"is_active": False})
    client.post(f"/tickets/{_ticket(db, TLS).id}/assign", headers=as_("manager"), json={"assignee_id": None})
    prev = client.post(f"/projects/{linked}/rules/apply", headers=as_("manager"), json={"dry_run": True}).json()
    item = next(i for i in prev["items"] if i["title"] == TLS)
    assert item["rule"] is None and "некому назначить" in item["note"]


def test_rules_crud_validation_order_and_permissions(client, as_, linked, users, db):
    url = f"/projects/{linked}/rules"
    body = {"name": "Ядро", "kinds": ["kernel"], "assignee_id": users["engineer"].id}
    assert client.post(url, headers=as_("engineer"), json=body).status_code == 403
    assert client.post(url, headers=as_("admin"), json=body).status_code == 403
    bad = [
        ({**body, "team_id": 1}, "исполнителя или команду"),
        ({"name": "x"}, "исполнителя или команду"),
        ({**body, "kinds": ["rootkit"]}, "Неизвестный вид"),
        ({**body, "assignee_id": users["viewer"].id}, "не может работать"),
        ({"name": "x", "team_id": 999}, "Команда не найдена"),
    ]
    for b, msg in bad:
        r = client.post(url, headers=as_("manager"), json=b)
        assert r.status_code == 422 and msg in r.text, (b, r.text)
    a = _rule(client, as_, linked, **body)
    b = _rule(
        client,
        as_,
        linked,
        name="Теги",
        tags=[" PROD ", "prod"],
        owners=["Группа СУБД"],
        assignee_id=users["manager"].id,
    )
    assert b["tags"] == ["prod"] and b["owners"] == ["Группа СУБД"] and b["host_match"] == "all"
    # Порядок: передать нужно все правила.
    assert client.put(f"{url}/order", headers=as_("manager"), json={"ids": [b["id"]]}).status_code == 422
    r = client.put(f"{url}/order", headers=as_("manager"), json={"ids": [b["id"], a["id"]]})
    assert [x["id"] for x in r.json()] == [b["id"], a["id"]]
    assert [x["id"] for x in client.get(url, headers=as_("viewer")).json()] == [b["id"], a["id"]]
    # Правка цели: команда вместо исполнителя.
    team = client.post("/teams", headers=as_("manager"), json={"name": "Linux", "member_ids": [users["engineer"].id]})
    r = client.patch(
        f"/rules/{a['id']}", headers=as_("manager"), json={"team_id": team.json()["id"], "is_active": False}
    )
    assert r.status_code == 200 and r.json()["team"]["name"] == "Linux" and r.json()["assignee"] is None
    assert r.json()["is_active"] is False
    assert client.delete(f"/teams/{team.json()['id']}", headers=as_("manager")).status_code == 409
    assert client.delete(f"/rules/{a['id']}", headers=as_("manager")).status_code == 204
    assert client.delete(f"/teams/{team.json()['id']}", headers=as_("manager")).status_code == 204
    actions = set(
        db.scalars(select(AuditLog.action).where(AuditLog.action.like("rule.%") | AuditLog.action.like("team.%")))
    )
    assert actions == {"rule.create", "rule.update", "rule.delete", "rule.reorder", "team.create", "team.delete"}
    assert db.scalar(select(AssignmentRule).where(AssignmentRule.id == a["id"])) is None


def test_teams_validation(client, as_, users):
    assert client.post("/teams", headers=as_("engineer"), json={"name": "X"}).status_code == 403
    r = client.post("/teams", headers=as_("manager"), json={"name": "X", "member_ids": [users["viewer"].id]})
    assert r.status_code == 422 and "Не могут работать" in r.text
    assert client.post("/teams", headers=as_("manager"), json={"name": "Linux"}).status_code == 201
    assert client.post("/teams", headers=as_("manager"), json={"name": "linux"}).status_code == 409
    t = client.get("/teams", headers=as_("viewer")).json()[0]
    r = client.patch(
        f"/teams/{t['id']}", headers=as_("manager"), json={"member_ids": [users["engineer"].id, users["manager"].id]}
    )
    assert [m["username"] for m in r.json()["members"]] == ["engineer", "manager"]


def test_matches_all_any_and_host_without_asset():
    g = AssetGroup(name="DMZ")
    a1 = Asset(address="h1", owner="A", tags=["prod"])
    a1.groups = [g]
    a2 = Asset(address="h2", owner="B", tags=[])
    a2.groups = []
    t = Ticket(kind="package", os="Debian 12")
    t.hosts = [
        TicketHost(host="h1", status="open"),
        TicketHost(host="h2", status="open"),
        TicketHost(host="h3", status="confirmed"),
    ]
    assets = {"h1": a1, "h2": a2}

    def R(**kw):
        base = {"groups": [], "tags": [], "owners": [], "os": [], "kinds": [], "host_match": "all"}
        return AssignmentRule(**{**base, **kw})

    assert rules.matches(R(), t, assets)
    assert rules.matches(R(os=["Debian 12"], kinds=["package"]), t, assets)
    assert not rules.matches(R(kinds=["kernel"]), t, assets)
    assert not rules.matches(R(groups=["DMZ"]), t, assets)
    assert rules.matches(R(groups=["DMZ"], host_match="any"), t, assets)
    assert rules.matches(R(owners=["A", "B"]), t, assets)
    assert not rules.matches(R(owners=["A"], tags=["prod"]), t, assets)
    # Подтверждённый хост не учитывается; хост без актива условиям по хостам не удовлетворяет.
    t.hosts[1].status = "confirmed"
    assert rules.matches(R(groups=["DMZ"]), t, assets)
    t.hosts[0].host = "unknown"
    assert not rules.matches(R(groups=["DMZ"], host_match="any"), t, assets)


# --- группа активов в фильтре заявок и в охвате окон ---


def test_ticket_filter_and_facets_by_group(client, as_, linked, db):
    _import(client, as_, linked)
    url = f"/projects/{linked}/tickets"
    dmz = client.get(url, headers=as_("viewer"), params={"group": "DMZ", "limit": 100}).json()
    titles = {t["title"] for t in dmz}
    assert {TLS, LIBSSL, SSH_DEB} <= titles and TOMCAT not in titles and BIND not in titles
    assert client.get(url, headers=as_("viewer"), params={"group": "Резерв"}).json() == []
    facets = client.get(f"/projects/{linked}/ticket-facets", headers=as_("viewer")).json()
    groups = {g["id"]: g for g in facets["groups"]}
    assert groups["DMZ"]["total"] == len(dmz) and groups["Резерв"] == {"id": "Резерв", "total": 0, "open": 0}


def _daily(client, as_, pid, **kw) -> dict:
    start = (datetime.now(UTC) + timedelta(hours=1)).astimezone(windows.tz_of("Europe/Moscow"))
    body = {
        "name": "Ночное окно",
        "kind": "recurring",
        "weekdays": list(range(7)),
        "start_time": f"{start:%H}:00",
        "duration_minutes": 240,
        **kw,
    }
    r = client.post(f"/projects/{pid}/windows", headers=as_("manager"), json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_window_scope_by_asset_group(client, as_, linked, db):
    _import(client, as_, linked)
    w = _daily(client, as_, linked, groups=[" DMZ ", "DMZ"], hosts=["10.20.1.17"])
    assert w["groups"] == ["DMZ"] and w["hosts"] == ["10.20.1.17"]
    ssh = _ticket(db, SSH_DEB)
    r = client.post(f"/tickets/{ssh.id}/window", headers=as_("manager"), json={"window_id": w["id"]})
    assert r.status_code == 200, r.text
    plan = client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()["plan"]
    item = next(i for i in plan["items"] if i["ticket_id"] == ssh.id)
    assert sorted(item["hosts"]) == sorted([*DMZ, "10.20.1.17"])
    assert {s["reason"] for s in item["skipped_hosts"]} == {"не входит в окно"}
    # Блэкаут на группу закрывает её хосты.
    nxt = client.get(f"/windows/{w['id']}", headers=as_("viewer")).json()["next"]
    client.post(
        f"/projects/{linked}/windows",
        headers=as_("manager"),
        json={
            "name": "Заморозка DMZ",
            "kind": "blackout",
            "starts_at": nxt["start"],
            "ends_at": nxt["end"],
            "groups": ["DMZ"],
        },
    )
    plan = client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()["plan"]
    item = next(i for i in plan["items"] if i["ticket_id"] == ssh.id)
    assert item["hosts"] == ["10.20.1.17"] and sorted(plan["occurrence"]["blocked_hosts"]) == DMZ
    # Окно на пустую группу: заявку в него не поставить.
    empty = _daily(client, as_, linked, name="Резервное", groups=["Резерв"])
    tls = _ticket(db, TLS)
    r = client.post(f"/tickets/{tls.id}/window", headers=as_("manager"), json={"window_id": empty["id"]})
    assert r.status_code == 409 and "Ни один хост" in r.text
    # Состав группы берётся на момент расчёта: is_open для раскаток видит хост группы.
    db.expire_all()
    win = db.get(type(ssh).window.property.mapper.class_, w["id"])
    start = datetime.fromisoformat(nxt["start"]) + timedelta(minutes=1)
    assert windows.is_open(db, win, "10.20.1.17", start)
    assert not windows.is_open(db, win, DMZ[0], start)  # закрыт блэкаутом
    assert not windows.is_open(db, win, "10.20.3.36", start)  # вне окна
