"""Задача 3.1: отчёт о ходе устранения — данные за период, разбивки и форматы HTML/PDF/DOCX/JSON."""

import io
import zipfile
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app.db import utcnow
from app.models import AuditLog, Ticket, TicketException

PERIOD = {"from": "2026-09-01", "to": "2026-11-05"}


@pytest.fixture()
def project(client, as_):
    pid = client.post(
        "/projects", headers=as_("admin"), json={"name": "Порт", "client": "АО «Порт»", "contract_ref": "Д-17"}
    ).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    assert client.post(f"/projects/{pid}/assets/sync", headers=as_("engineer")).status_code == 200
    return pid


def _json(client, h, pid, **params) -> dict:
    r = client.get(f"/projects/{pid}/report", headers=h, params={"format": "json", **PERIOD, **params})
    assert r.status_code == 200, r.text
    return r.json()


def test_movement_adds_up_and_matches_lists(client, as_, project):
    h = as_("viewer")
    r = _json(client, h, project)
    v = r["totals"]["vulns"]
    # Тождество движения: на конец = на начало + появилось + регрессии − закрыто — в целом и по каждому срезу.
    for row in [v, *r["by_severity"], *r["groups"]]:
        assert row["end"] == row["start"] + row["appeared"] + row["regression"] - row["fixed"], row
    assert sum(s["end"] for s in r["by_severity"]) == v["end"]
    assert v["start"] == 0 and v["appeared"] > 0 and v["fixed"] > 0 and v["regression"] >= 1
    # На конец периода (после последнего прогона) — ровно открытые сейчас.
    open_now = client.get(f"/projects/{project}/vulnerabilities", headers=h, params={"state": "open", "limit": 1})
    assert v["end"] == int(open_now.headers["X-Total-Count"])
    # Прогоны: события по прогонам складываются в итог периода.
    assert [x["scanner_run_id"] for x in r["runs"]] == [100, 101, 102]
    assert sum(x["fixed"] for x in r["runs"]) == v["fixed"]
    assert sum(x["appeared"] for x in r["runs"]) == v["appeared"]
    # Недели: сумма «появилось» (с регрессиями) и «закрыто».
    assert sum(sum(w["opened"].values()) for w in r["weeks"]) == v["appeared"] + v["regression"]
    assert sum(sum(w["closed"].values()) for w in r["weeks"]) == v["fixed"]
    # Заявки: подтверждённые за период — с доказательством, открытые — все незакрытые.
    tickets = client.get(f"/projects/{project}/tickets", headers=h, params={"limit": 500}).json()
    verified = [t for t in tickets if t["status"] == "verified"]
    assert {t["id"] for t in r["verified"]} == {t["id"] for t in verified} and verified
    assert all(t["evidence"]["scanner_run_id"] == 102 and t["closed_local"] == "03.11.2026" for t in r["verified"])
    assert (
        r["totals"]["tickets_open"]
        == len(r["remaining"])
        == len([t for t in tickets if t["status"] not in ("verified", "risk_accepted", "false_positive")])
    )
    sev_rank = ["critical", "high", "medium", "low", "info"]
    ranks = [sev_rank.index(t["severity"]) for t in r["remaining"]]
    assert ranks == sorted(ranks)
    # Группы активов из «Сканера» и хосты без группы.
    names = {g["name"] for g in r["groups"]}
    assert {"DMZ", "Базы данных"} <= names
    assert r["context"]["deadlines"] is False
    assert r["context"]["project"]["contract_ref"] == "Д-17"
    assert r["key_points"] and "11 уязвимостей" in r["key_points"][0]


def test_period_boundaries_split_runs(client, as_, project):
    h = as_("viewer")
    full = _json(client, h, project)["totals"]["vulns"]
    sept = _json(client, h, project, **{"from": "2026-09-01", "to": "2026-09-30"})
    later = _json(client, h, project, **{"from": "2026-10-01", "to": "2026-11-05"})
    # Сентябрьский прогон целиком в первом периоде, конец первого — начало второго.
    assert [x["scanner_run_id"] for x in sept["runs"]] == [100]
    assert sept["totals"]["vulns"]["end"] == later["totals"]["vulns"]["start"] == sept["totals"]["vulns"]["appeared"]
    assert later["totals"]["vulns"]["end"] == full["end"]
    assert later["totals"]["vulns"]["fixed"] == full["fixed"]
    # Подтверждение заявок — по дате прогона-доказательства (3 ноября), а не по дате импорта.
    assert sept["verified"] == [] and later["verified"]
    # Граница дня — по часовому поясу: прогон 2026-09-08 21:40 UTC — это уже 9 сентября в Москве.
    nine = _json(client, h, project, **{"from": "2026-09-09", "to": "2026-09-09"})
    utc = _json(client, h, project, **{"from": "2026-09-09", "to": "2026-09-09", "tz": "UTC"})
    assert nine["totals"]["vulns"]["appeared"] > 0 and utc["totals"]["vulns"]["appeared"] == 0


def test_assignees_and_exceptions(client, as_, project, users, db):
    h = as_("viewer")
    tickets = client.get(f"/projects/{project}/tickets", headers=h, params={"limit": 500}).json()
    new = [t for t in tickets if t["status"] == "new"]
    assert client.post(f"/tickets/{new[0]['id']}/take", headers=as_("engineer")).status_code == 200
    # Действующее исключение — строкой в отчёте; заявка уходит из «осталось».
    t = db.get(Ticket, new[1]["id"])
    t.status = "risk_accepted"
    db.add(
        TicketException(
            project_id=project,
            ticket_id=t.id,
            kind="risk_accepted",
            status="active",
            reason="Сервер выводится из эксплуатации",
            measures="Доступ закрыт межсетевым экраном",
            review_on=date(2027, 1, 15),
            approver_id=users["manager"].id,
            decided_at=utcnow(),
            hosts=["10.20.1.11"],
            vuln_count=2,
        )
    )
    db.commit()
    r = _json(client, h, project)
    eng = next(p for p in r["assignees"] if p["name"] == "Engineer")
    assert eng["open"] == eng["in_work"] == 1 and eng["by_severity"][new[0]["severity"]] == 1
    free = next(p for p in r["assignees"] if p["name"] == "Не назначено")
    assert sum(p["open"] for p in r["assignees"]) == r["totals"]["tickets_open"]
    assert free["verified"] == len(r["verified"])
    assert r["assignees"][-1]["name"] == "Не назначено"
    [ex] = r["exceptions"]
    assert ex["ticket_id"] == t.id and ex["approver"] == "Manager" and ex["review_local"] == "15.01.2027"
    assert t.id not in {x["id"] for x in r["remaining"]}
    assert r["totals"]["tickets_exceptions"] == 1


def test_formats_and_escaping(client, as_, project, db):
    t = db.scalars(select(Ticket).where(Ticket.project_id == project, Ticket.status == "new")).first()
    t.title = '<script>alert(1)</script> Обновить "пакет"'
    db.commit()
    h = as_("viewer")

    r = client.get(f"/projects/{project}/report", headers=h, params={"format": "html", **PERIOD})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.headers["content-disposition"] == (
        f'attachment; filename="vm-report-{project}-2026-09-01-2026-11-05.html"'
    )
    assert "default-src 'none'" in r.headers["content-security-policy"]
    body = r.text
    assert "<script>" not in body and "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "Отчёт о ходе устранения уязвимостей" in body and "АО «Порт»" in body
    assert 'data-chart="waterfall"' in body and 'data-chart="weeks"' in body and 'data-chart="severity"' in body
    assert "<script" not in body.lower()

    r = client.get(f"/projects/{project}/report", headers=h, params={"format": "html", "download": "0", **PERIOD})
    assert r.headers["content-disposition"].startswith("inline;")

    r = client.get(f"/projects/{project}/report", headers=h, params={"format": "pdf", **PERIOD})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")

    r = client.get(f"/projects/{project}/report", headers=h, params={"format": "docx", **PERIOD})
    assert r.status_code == 200 and "wordprocessingml" in r.headers["content-type"]
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        xml = z.read("word/document.xml").decode()
        assert any(n.startswith("word/media/") for n in z.namelist())  # графики PNG
    assert "Отчёт о ходе устранения уязвимостей" in xml and "&lt;script&gt;" in xml

    brief = _json(client, h, project, variant="brief")
    assert brief["verified"] == [] and brief["remaining"] == [] and brief["context"]["variant"] == "brief"
    assert brief["totals"]["tickets_open"] > 0
    html = client.get(f"/projects/{project}/report", headers=h, params={"format": "html", "variant": "brief", **PERIOD})
    assert "Список заявок — в полной версии отчёта" in html.text

    rows = db.scalars(select(AuditLog).where(AuditLog.action == "report.export")).all()
    # Предпросмотр (download=0) в журнал не пишется — только выгрузки файлов.
    assert len(rows) == 5 and rows[0].project_id == project and rows[0].username == "viewer"
    assert {r.details["format"] for r in rows} == {"html", "pdf", "docx", "json"}


def test_validation_and_access(client, as_, project):
    h = as_("viewer")
    url = f"/projects/{project}/report"
    tomorrow = (date.today() + timedelta(days=2)).isoformat()
    assert client.get(url, headers=h, params={"from": "2026-10-02", "to": "2026-10-01"}).status_code == 422
    assert client.get(url, headers=h, params={"to": tomorrow}).status_code == 422
    assert client.get(url, headers=h, params={"from": "2020-01-01", "to": "2026-01-01"}).status_code == 422
    assert client.get(url, headers=h, params={"tz": "Mars/Base"}).status_code == 422
    assert client.get(url, headers=h, params={"format": "xlsx"}).status_code == 422
    assert client.get(url, headers=h, params={"variant": "huge"}).status_code == 422
    assert client.get("/projects/nope/report", headers=h).status_code == 404
    assert client.get(url).status_code == 401
    # По умолчанию — 90 дней до сегодня.
    r = client.get(url, headers=as_("engineer"), params={"format": "json"}).json()
    assert r["context"]["period"]["days"] == 91
    meta = client.get("/report-meta", headers=h).json()
    assert [f["id"] for f in meta["formats"]] == ["html", "pdf", "docx", "json"] and meta["deadlines"] is False
