"""Задача 2.1: окна обслуживания (разовые, повторяющиеся, блэкауты) и план «закроет N уязвимостей»."""

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import AuditLog, MaintenanceWindow, Outbox, Ticket, Vulnerability
from app.services import windows
from app.services.windows import Occurrence, WindowError

SSH_DEB = "Обновить openssh-server на Debian 12 до 1:9.2p1-2+deb12u3"
KERNEL_PREFIX = "Обновить ядро"
DEB_HOSTS = [f"10.20.1.{i}" for i in range(11, 19)]


def W(**kw) -> MaintenanceWindow:
    base = {"id": 1, "project_id": "p", "name": "Окно", "kind": "recurring", "timezone": "Europe/Moscow"}
    base.update(kw)
    w = MaintenanceWindow(**base)
    w.is_active = kw.get("is_active", True)
    w.hosts = kw.get("hosts", [])
    return w


# --- расписание ---


def test_recurring_crosses_midnight_in_window_timezone():
    # «Вторник 22:00–02:00» по Москве (UTC+3): 19:00–23:00 UTC вторника.
    w = W(weekdays=[1], start_time="22:00", duration_minutes=240)
    windows.validate(w)
    got = windows.intervals(w, datetime(2026, 11, 2, tzinfo=UTC), datetime(2026, 11, 16, tzinfo=UTC))
    assert got == [
        (datetime(2026, 11, 3, 19, tzinfo=UTC), datetime(2026, 11, 3, 23, tzinfo=UTC)),
        (datetime(2026, 11, 10, 19, tzinfo=UTC), datetime(2026, 11, 10, 23, tzinfo=UTC)),
    ]
    assert windows.schedule_text(w) == "вт 22:00–02:00 (Europe/Moscow)"
    # Окно, которое уже идёт, попадает в диапазон, начатый внутри него.
    inside = windows.intervals(w, datetime(2026, 11, 3, 22, tzinfo=UTC), datetime(2026, 11, 4, tzinfo=UTC))
    assert inside == [(datetime(2026, 11, 3, 19, tzinfo=UTC), datetime(2026, 11, 3, 23, tzinfo=UTC))]


def test_recurring_respects_validity_dates_and_other_timezone():
    w = W(
        weekdays=[0, 3],
        start_time="01:30",
        duration_minutes=60,
        timezone="Asia/Yekaterinburg",
        valid_from=date(2026, 11, 5),
        valid_until=date(2026, 11, 12),
    )
    windows.validate(w)
    got = windows.intervals(w, datetime(2026, 11, 1, tzinfo=UTC), datetime(2026, 11, 30, tzinfo=UTC))
    # чт 05.11, пн 09.11, чт 12.11 в 01:30 по Екатеринбургу (UTC+5) — накануне в 20:30 UTC.
    assert [s for s, _ in got] == [
        datetime(2026, 11, 4, 20, 30, tzinfo=UTC),
        datetime(2026, 11, 8, 20, 30, tzinfo=UTC),
        datetime(2026, 11, 11, 20, 30, tzinfo=UTC),
    ]


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"weekdays": []}, "дни недели"),
        ({"weekdays": [7]}, "дни недели"),
        ({"start_time": "24:00"}, "ЧЧ:ММ"),
        ({"duration_minutes": 5}, "Длительность"),
        ({"timezone": "Mars/Base"}, "часовой пояс"),
        ({"hosts": ["10.0.0.1; rm -rf /"]}, "имя хоста"),
        ({"valid_from": date(2026, 12, 1), "valid_until": date(2026, 11, 1)}, "раньше"),
    ],
)
def test_recurring_validation(kw, message):
    base = {"weekdays": [1], "start_time": "22:00", "duration_minutes": 240}
    with pytest.raises(WindowError, match=message):
        windows.validate(W(**{**base, **kw}))


def test_once_validation():
    s = datetime(2026, 11, 20, 19, tzinfo=UTC)
    with pytest.raises(WindowError, match="позже"):
        windows.validate(W(kind="once", starts_at=s, ends_at=s))
    with pytest.raises(WindowError, match="7 суток"):
        windows.validate(W(kind="once", starts_at=s, ends_at=s + timedelta(days=8)))
    # Блэкаут может быть длинным (праздники, закрытие квартала).
    b = W(kind="blackout", starts_at=s, ends_at=s + timedelta(days=12), weekdays=[1], start_time="22:00")
    windows.validate(b)
    assert (b.weekdays, b.start_time) == ([], "")


def test_blackout_cancels_whole_date_or_only_its_hosts():
    w = W(id=1, weekdays=[1, 3], start_time="22:00", duration_minutes=240)
    # Блэкаут на весь проект задевает вторник 10.11 лишь краем — дата выпадает целиком.
    all_ = W(id=2, kind="blackout", starts_at=datetime(2026, 11, 10, 22, 30, tzinfo=UTC))
    all_.ends_at = datetime(2026, 11, 11, 6, tzinfo=UTC)
    some = W(id=3, kind="blackout", hosts=["10.20.1.11"], starts_at=datetime(2026, 11, 12, tzinfo=UTC))
    some.ends_at = datetime(2026, 11, 13, tzinfo=UTC)
    occ = windows.occurrences([w, all_, some], datetime(2026, 11, 9, tzinfo=UTC), datetime(2026, 11, 14, tzinfo=UTC))
    assert [(o.start.day, o.cancelled, o.blocked_hosts) for o in occ] == [(10, True, None), (12, False, {"10.20.1.11"})]
    assert not occ[1].host_allowed("10.20.1.11") and occ[1].host_allowed("10.20.1.12")
    # Окно только на заблокированные хосты выпадает целиком.
    narrow = W(id=4, weekdays=[3], start_time="22:00", duration_minutes=60, hosts=["10.20.1.11"])
    o = windows.occurrences([narrow, some], datetime(2026, 11, 12, tzinfo=UTC), datetime(2026, 11, 13, tzinfo=UTC))
    assert o[0].cancelled
    # Отключённый блэкаут ничего не запрещает.
    all_.is_active = False
    occ = windows.occurrences([w, all_], datetime(2026, 11, 10, tzinfo=UTC), datetime(2026, 11, 11, tzinfo=UTC))
    assert not occ[0].cancelled


def test_estimate_canary_then_batches_of_ten_percent():
    assert windows.estimate_minutes("package", 0, False) == 0
    assert windows.estimate_minutes("package", 1, False) == 10
    assert windows.estimate_minutes("package", 8, False) == 80  # партии по 1 хосту
    assert windows.estimate_minutes("package", 21, False) == (1 + 7) * 10  # партии по 3 хоста
    assert windows.estimate_minutes("kernel", 2, True) == 2 * 25


# --- API ---


@pytest.fixture()
def project(client, as_):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={"scanner_run_id": 100}).json()
    assert job["status"] == "done", job
    return pid


def _daily(client, as_, pid, **kw) -> dict:
    """Ежедневное окно, которое начинается через час: у него всегда есть ближайшая дата."""
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


def _tid(db, title) -> int:
    db.expire_all()
    return db.scalars(select(Ticket.id).where(Ticket.title == title)).one()


def test_windows_crud_and_permissions(client, as_, project, db):
    w = _daily(client, as_, project)
    assert w["kind_label"] == "Повторяющееся" and w["next"] and not w["next"]["cancelled"]
    assert w["schedule"].startswith("пн, вт, ср, чт, пт, сб, вс ")
    # Окна настраивает руководитель: исполнитель, наблюдатель и администратор — нет.
    for who in ("engineer", "viewer", "admin"):
        r = client.post(f"/projects/{project}/windows", headers=as_(who), json={"name": "x", "kind": "once"})
        assert r.status_code == 403, who
    assert len(client.get(f"/projects/{project}/windows", headers=as_("viewer")).json()) == 1
    bad = client.post(
        f"/projects/{project}/windows",
        headers=as_("manager"),
        json={"name": "x", "kind": "once", "starts_at": "2026-11-20T22:00:00+03:00"},
    )
    assert bad.status_code == 422 and "начало и конец" in bad.json()["detail"]
    r = client.patch(f"/windows/{w['id']}", headers=as_("manager"), json={"duration_minutes": 120, "name": " Ночь "})
    assert r.status_code == 200 and r.json()["duration_minutes"] == 120 and r.json()["name"] == "Ночь"
    assert client.patch(f"/windows/{w['id']}", headers=as_("manager"), json={"start_time": "7:00"}).status_code == 422
    assert client.delete(f"/windows/{w['id']}", headers=as_("manager")).status_code == 204
    actions = db.scalars(select(AuditLog.action).where(AuditLog.action.like("window.%")).order_by(AuditLog.id)).all()
    assert actions == ["window.create", "window.update", "window.delete"]


def test_place_ticket_moves_status_and_plan_counts_vulnerabilities(client, as_, project, users, db):
    w = _daily(client, as_, project)
    tid = _tid(db, SSH_DEB)
    # Свободную заявку ставит только руководитель; статус «Новая» не меняется.
    r = client.post(f"/tickets/{tid}/window", headers=as_("engineer"), json={"window_id": w["id"]})
    assert r.status_code == 403
    denied = db.scalars(select(AuditLog).where(AuditLog.action == "ticket.window")).one()
    assert denied.result == "denied"
    client.post(f"/tickets/{tid}/take", headers=as_("engineer"))
    # Исполнитель ставит свою заявку: «Назначена» → «Ожидает окна».
    r = client.post(f"/tickets/{tid}/window", headers=as_("engineer"), json={"window_id": w["id"]})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "waiting_window" and r.json()["window"] == {"id": w["id"], "name": w["name"]}
    card = client.get(f"/tickets/{tid}", headers=as_("engineer")).json()
    assert card["can"]["window"] is True
    hist = client.get(f"/tickets/{tid}/history", headers=as_("viewer")).json()["history"]
    assert [h["action"] for h in hist][-2:] == ["window", "status"]
    assert db.scalars(select(Outbox).where(Outbox.type == "vm.ticket.scheduled")).first() is not None

    plan = client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()
    p = plan["plan"]
    open_vulns = db.scalars(
        select(Vulnerability).where(Vulnerability.ticket_id == tid, Vulnerability.state == "open")
    ).all()
    assert len(p["items"]) == 1 and p["items"][0]["fits"]
    assert p["items"][0]["hosts"] == sorted({v.host for v in open_vulns})
    assert p["will_close"] == len(open_vulns) > 0
    assert p["hosts"] == len({v.host for v in open_vulns})
    assert p["items"][0]["estimate_minutes"] == windows.estimate_minutes("package", p["hosts"], False)
    assert plan["window"]["tickets"] == 1
    # Снять с окна: «Ожидает окна» → «В работе».
    r = client.post(f"/tickets/{tid}/window", headers=as_("engineer"), json={"window_id": None})
    assert r.json()["status"] == "in_progress" and r.json()["window"] is None
    assert client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()["plan"]["will_close"] == 0


def test_plan_respects_scope_blackout_and_overflow(client, as_, project, db):
    # Окно только на два Debian-хоста, длительностью 15 минут: ядро с перезагрузкой не поместится.
    w = _daily(client, as_, project, hosts=DEB_HOSTS[:2], duration_minutes=30)
    ssh = _tid(db, SSH_DEB)
    kernel = db.scalars(select(Ticket).where(Ticket.title.like(f"{KERNEL_PREFIX}%"), Ticket.os.like("Debian%"))).first()
    for tid in (ssh, kernel.id):
        r = client.post(f"/tickets/{tid}/window", headers=as_("manager"), json={"window_id": w["id"]})
        assert r.status_code == 200, r.text
    p = client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()["plan"]
    by_id = {i["ticket_id"]: i for i in p["items"]}
    assert by_id[ssh]["hosts"] == DEB_HOSTS[:2]
    assert {s["reason"] for s in by_id[ssh]["skipped_hosts"]} == {"не входит в окно"}
    fits = [i for i in p["items"] if i["fits"]]
    over = [i for i in p["items"] if i["hosts"] and not i["fits"]]
    assert fits and over and p["overflow_tickets"] == len(over)
    assert p["will_close"] == sum(i["vulns"] for i in fits)
    assert p["overflow_vulns"] == sum(i["vulns"] for i in over)
    assert any(i["reboot"] for i in p["items"])
    # Блэкаут на один хост окна: хост выпадает из плана с причиной «блэкаут».
    nxt = client.get(f"/windows/{w['id']}", headers=as_("viewer")).json()["next"]
    r = client.post(
        f"/projects/{project}/windows",
        headers=as_("manager"),
        json={
            "name": "Заморозка",
            "kind": "blackout",
            "starts_at": nxt["start"],
            "ends_at": nxt["end"],
            "hosts": [DEB_HOSTS[0]],
        },
    )
    assert r.status_code == 201, r.text
    p = client.get(f"/windows/{w['id']}/plan", headers=as_("viewer")).json()["plan"]
    item = next(i for i in p["items"] if i["ticket_id"] == ssh)
    assert item["hosts"] == [DEB_HOSTS[1]]
    assert {"host": DEB_HOSTS[0], "reason": "блэкаут"} in item["skipped_hosts"]
    assert p["occurrence"]["blocked_hosts"] == [DEB_HOSTS[0]]


def test_place_rules(client, as_, project, db):
    tid = _tid(db, SSH_DEB)
    other = _daily(client, as_, project, hosts=["10.99.0.1"])
    r = client.post(f"/tickets/{tid}/window", headers=as_("manager"), json={"window_id": other["id"]})
    assert r.status_code == 409 and "Ни один хост" in r.json()["detail"]
    s = datetime.now(UTC) - timedelta(days=2)
    past = client.post(
        f"/projects/{project}/windows",
        headers=as_("manager"),
        json={
            "name": "Прошлое",
            "kind": "once",
            "starts_at": s.isoformat(),
            "ends_at": (s + timedelta(hours=2)).isoformat(),
        },
    ).json()
    assert past["past"] is True and past["next"] is None
    r = client.post(f"/tickets/{tid}/window", headers=as_("manager"), json={"window_id": past["id"]})
    assert r.status_code == 409 and "нет предстоящих дат" in r.json()["detail"]
    # Блэкаут на весь проект на ближайшие сутки — у ежедневного окна следующая дата — завтра.
    daily = _daily(client, as_, project)
    first = daily["next"]["start"]
    client.post(
        f"/projects/{project}/windows",
        headers=as_("manager"),
        json={"name": "Стоп", "kind": "blackout", "starts_at": first, "ends_at": daily["next"]["end"]},
    )
    again = client.get(f"/windows/{daily['id']}", headers=as_("viewer")).json()
    assert again["next"]["start"] > first
    plan = client.get(f"/windows/{daily['id']}/plan", headers=as_("viewer")).json()
    assert plan["plan"]["occurrence"]["cancelled"] is True and plan["next"]
    # Отключённое окно не принимает заявки; окно с заявками не удалить.
    client.post(f"/tickets/{tid}/window", headers=as_("manager"), json={"window_id": daily["id"]})
    r = client.delete(f"/windows/{daily['id']}", headers=as_("manager"))
    assert r.status_code == 409
    client.patch(f"/windows/{daily['id']}", headers=as_("manager"), json={"is_active": False})
    t2 = _tid(db, "Настроить: Разрешены устаревшие протоколы TLS 1.0 и TLS 1.1")
    r = client.post(f"/tickets/{t2}/window", headers=as_("manager"), json={"window_id": daily["id"]})
    assert r.status_code == 409 and "отключено" in r.json()["detail"]


def test_bulk_window_and_filters(client, as_, project, db):
    w = _daily(client, as_, project)
    ids = list(db.scalars(select(Ticket.id).where(Ticket.project_id == project).order_by(Ticket.id)))
    r = client.post(
        f"/projects/{project}/tickets/bulk",
        headers=as_("manager"),
        json={"ticket_ids": ids, "action": "window", "window_id": w["id"]},
    )
    out = r.json()
    assert r.status_code == 200 and out["changed"]
    # Закрытые заявки («Подтверждено» после трёх прогонов в демо нет — после одного прогона все открыты).
    assert len(out["changed"]) + len(out["failed"]) == len(ids)
    in_window = client.get(f"/projects/{project}/tickets?window={w['id']}&limit=500", headers=as_("viewer")).json()
    assert {t["id"] for t in in_window} == set(out["changed"])
    none = client.get(f"/projects/{project}/tickets?window=none&limit=500", headers=as_("viewer")).json()
    assert {t["id"] for t in none} == {f["id"] for f in out["failed"]}
    assert client.get(f"/projects/{project}/tickets?window=x", headers=as_("viewer")).status_code == 422
    # Массовое действие — только руководитель.
    r = client.post(
        f"/projects/{project}/tickets/bulk",
        headers=as_("engineer"),
        json={"ticket_ids": ids[:1], "action": "window", "window_id": None},
    )
    assert r.status_code == 403


def test_calendar_and_summary_show_upcoming_windows(client, as_, project, db):
    w = _daily(client, as_, project)
    client.post(f"/tickets/{_tid(db, SSH_DEB)}/window", headers=as_("manager"), json={"window_id": w["id"]})
    cal = client.get(f"/projects/{project}/calendar", headers=as_("viewer")).json()
    dates = [i for i in cal["items"] if i["window_id"] == w["id"]]
    assert 27 <= len(dates) <= 29 and dates[0]["will_close"] > 0 and dates[0]["tickets"] == 1
    too_long = client.get(
        f"/projects/{project}/calendar",
        params={"from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z"},
        headers=as_("viewer"),
    )
    assert too_long.status_code == 422
    s = client.get(f"/projects/{project}/summary", headers=as_("viewer")).json()
    assert len(s["upcoming_windows"]) == 5
    assert s["upcoming_windows"][0]["window_name"] == "Ночное окно" and s["upcoming_windows"][0]["will_close"] > 0


def test_is_open_for_rollouts(db, client, as_, project):
    w = _daily(client, as_, project, hosts=DEB_HOSTS[:1])
    win = db.get(MaintenanceWindow, w["id"])
    start = datetime.fromisoformat(w["next"]["start"])
    assert windows.is_open(db, win, DEB_HOSTS[0], start + timedelta(minutes=5))
    assert not windows.is_open(db, win, DEB_HOSTS[1], start + timedelta(minutes=5))
    assert not windows.is_open(db, win, DEB_HOSTS[0], start - timedelta(minutes=5))
    win.is_active = False
    assert not windows.is_open(db, win, DEB_HOSTS[0], start + timedelta(minutes=5))


def test_occurrence_out_shape():
    w = W(weekdays=[1], start_time="22:00", duration_minutes=60)
    o = Occurrence(w, datetime(2026, 11, 3, 19, tzinfo=UTC), datetime(2026, 11, 3, 20, tzinfo=UTC))
    assert o.out()["blocked_hosts"] == [] and o.out()["cancelled"] is False
