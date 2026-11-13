"""Задача 2.4: раскатки — шаблоны, пробный прогон, четыре глаза, allowlist и окно в момент запуска,
канарейка, партии, порог ошибок, аварийный стоп, перезагрузка, версии «до/после», журнал.

Хосты — демо-стенд SSH (app/integrations/sshsim.py): настоящие SSH-серверы asyncssh в процессе,
пакеты и версии — из демо-фикстуры «Сканера»."""

from datetime import timedelta

import asyncssh
import pytest
from sqlalchemy import select

from app import jobs
from app.db import utcnow
from app.integrations.scanner import MockScanner
from app.integrations.sshsim import SshSim
from app.models import AuditLog, HostKey, Job, Rollout, RolloutHost, RolloutStep, Ticket, User
from app.security import hash_password
from app.services import rollout_templates as tpl
from app.services import rollouts as svc
from app.services import sshexec
from tests.conftest import PASSWORD

ASTRA_SSH = "Обновить openssh-server на Astra Linux 1.7 до 1:7.9p1-10+deb10u2+ci202407"
GLIBC = "Обновить glibc на РЕД ОС 7.3 до 2.35-9.el7"
SUDO = "S3cret-sudo-pass"


@pytest.fixture()
def sim(monkeypatch):
    s = SshSim.from_fixture(
        "test-secret", delay=0, on_patched=lambda h, p: MockScanner.shared("demo").patched.add((h, p))
    )
    monkeypatch.setattr(sshexec, "route", s.route)
    yield s
    s.close()


@pytest.fixture()
def project(client, as_, db, users):
    pid = client.post("/projects", headers=as_("admin"), json={"name": "Порт"}).json()["id"]
    src = client.post(
        "/sources", headers=as_("admin"), json={"name": "Сканер", "base_url": "mock://demo", "username": "svc"}
    ).json()
    client.post(f"/projects/{pid}/links", headers=as_("admin"), json={"source_id": src["id"], "engagement_id": 7})
    job = client.post(f"/projects/{pid}/import", headers=as_("engineer"), json={}).json()
    assert job["status"] == "done", job
    r = client.post(
        f"/projects/{pid}/ssh-credentials",
        headers=as_("manager"),
        json={"name": "deploy", "username": "deploy", "password": PASSWORD, "become_password": SUDO},
    )
    assert r.status_code == 201, r.text
    # Второй руководитель с правом запуска — для проверки «четырёх глаз».
    db.add(
        User(
            username="lead",
            display_name="Lead",
            roles=["manager"],
            extra_perms=["remediate_execute", "custom_commands"],
            password_hash=hash_password(PASSWORD),
        )
    )
    db.commit()
    return pid


def _ticket(db, title) -> Ticket:
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.title == title)).one()


def _create(client, as_, tid, who="engineer", **kw):
    body = {"template": "package", "manager": "apt"} | kw
    return client.post(f"/tickets/{tid}/rollouts", headers=as_(who), json=body)


def _prepared(client, as_, db, title=ASTRA_SSH, **kw) -> dict:
    t = _ticket(db, title)
    if t.assignee_id is None:
        client.post(f"/tickets/{t.id}/take", headers=as_("engineer"))
    d = client.get(f"/tickets/{t.id}/rollout-draft", headers=as_("engineer")).json()
    body = {k: d[k] for k in ("template", "manager", "packages", "fixed_version", "hosts", "canary_host")} | kw
    r = client.post(f"/tickets/{t.id}/rollouts", headers=as_("engineer"), json=body)
    assert r.status_code == 201, r.text
    ro = r.json()
    r = client.post(f"/rollouts/{ro['id']}/dry-run", headers=as_("engineer"))
    assert r.status_code == 202, r.text
    return client.get(f"/rollouts/{ro['id']}", headers=as_("engineer")).json()


def _approve(client, as_, rid, who="manager", **kw):
    body = {"outside_window": True, "outside_window_reason": "Согласовано с заказчиком"} | kw
    return client.post(f"/rollouts/{rid}/approve", headers=as_(who), json=body)


def _actions(db, action) -> list[AuditLog]:
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


# --- шаблоны ---


@pytest.mark.parametrize(
    "bad",
    ["openssl; rm -rf /", "$(id)", "-oProxyCommand=x", "pkg name", "pkg`id`", "a|b", "", "x" * 200, "пакет"],
)
def test_hostile_package_names_rejected(bad):
    with pytest.raises(tpl.TemplateError):
        tpl.check_name(bad)


def test_commands_are_argument_lists():
    assert tpl.upgrade_cmd("apt", ["libssl3"])[-1] == "libssl3"
    assert tpl.simulate_cmd("dnf", ["glibc"]) == ["dnf", "upgrade", "--assumeno", "glibc"]
    assert tpl.parse_command("systemctl restart 'my unit'") == ["systemctl", "restart", "my unit"]
    with pytest.raises(tpl.TemplateError):
        tpl.parse_command("echo 'oops")


def test_version_compare():
    assert tpl.deb_compare("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2") > 0
    assert tpl.deb_compare("1.0~rc1", "1.0") < 0
    assert tpl.rpm_compare("2.35-9.el7", "2.35-6.el7") > 0
    assert tpl.rpm_compare("1.10-1", "1.9-1") > 0


# --- подготовка ---


def test_prepare_requires_rights_and_clean_names(client, as_, db, project, sim):
    t = _ticket(db, ASTRA_SSH)
    assert client.get(f"/tickets/{t.id}", headers=as_("engineer")).json()["can"]["rollout"] is True
    assert client.get(f"/tickets/{t.id}", headers=as_("manager")).json()["can"]["rollout"] is False
    assert _create(client, as_, t.id, "manager", packages=["openssh-server"]).status_code == 403
    r = _create(client, as_, t.id, packages=["openssh-server; reboot"])
    assert r.status_code == 422 and "Недопустимое имя" in r.json()["detail"]
    assert _actions(db, "rollout.create")[-1].result == "denied"
    r = _create(client, as_, t.id, template="custom", command="id")
    assert r.status_code == 403
    r = _create(client, as_, t.id, packages=["openssh-server"], hosts=["10.99.0.1"])
    assert r.status_code == 422
    r = _create(client, as_, t.id, packages=["openssh-server"])
    assert r.status_code == 201
    assert _create(client, as_, t.id, packages=["openssh-server"]).status_code == 409  # одна открытая на заявку


def test_full_flow_canary_batches_versions_and_verification(client, as_, db, project, sim):
    ro = _prepared(client, as_, db, batch_percent=50)
    rid = ro["id"]
    assert ro["status"] == "pending_approval", ro
    by = {h["host"]: h for h in ro["hosts"]}
    assert set(by) == {"10.20.2.21", "10.20.2.22", "10.20.2.23", "10.20.2.24", "10.20.2.25", "10.20.2.26"}
    h21 = by["10.20.2.21"]
    assert h21["dry_status"] == "ok"
    assert h21["dry_plan"] == [
        {"package": "openssh-server", "from": "1:7.9p1-10+deb10u2+ci202306", "to": "1:7.9p1-10+deb10u2+ci202407"}
    ]
    assert h21["versions_before"] == {"openssh-server": "1:7.9p1-10+deb10u2+ci202306"}
    # Пробный прогон ничего не поменял.
    assert sim.hosts["10.20.2.21"].packages["openssh-server"].version == "1:7.9p1-10+deb10u2+ci202306"
    assert any(c[:4] == ["sudo", "-S", "-p", ""] and "-s" in c for c in sim.hosts["10.20.2.21"].commands)
    assert not any("install" in c and "-s" not in c for c in sim.hosts["10.20.2.21"].commands)

    # Четыре глаза: исполнитель не утверждает (нет права), утверждает руководитель.
    assert _approve(client, as_, rid, "engineer").status_code == 403
    assert client.post(f"/rollouts/{rid}/start", headers=as_("engineer")).status_code == 409  # не утверждена
    r = _approve(client, as_, rid, allow_reboot=False, note="ок")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["can"]["start"] is False  # утвердивший не запускает
    r = client.post(f"/rollouts/{rid}/start", headers=as_("engineer"))
    assert r.status_code == 202, r.text

    db.expire_all()
    r = db.get(Rollout, rid)
    assert r.status == "done", (r.status, r.error)
    stages = {h.host: h.stage for h in r.hosts}
    assert stages[r.canary_host] == 0
    assert sorted(stages.values()) == [0, 1, 1, 1, 2, 2]  # 50 % от 6 — по 3 хоста
    for h in r.hosts:
        assert h.status == "succeeded", (h.host, h.reason)
        assert h.versions_after == {"openssh-server": "1:7.9p1-10+deb10u2+ci202407"}
    out = client.get(f"/rollouts/{rid}", headers=as_("viewer")).json()
    assert out["hosts"][0]["rollback"] == ["apt-get install openssh-server=1:7.9p1-10+deb10u2+ci202306"]
    assert [s["state"] for s in out["stages"]][:4] == ["done", "done", "done", "done"]

    # Журнал: команды, коды, stdout; пароль sudo — только в stdin, не в журнале.
    steps = db.scalars(select(RolloutStep).where(RolloutStep.rollout_id == rid)).all()
    assert any(s.label == "Обновление" and s.returncode == 0 and "Setting up openssh-server" in s.stdout for s in steps)
    assert all(SUDO not in (s.command + s.stdout + s.stderr) and PASSWORD not in s.command for s in steps)
    upd = next(s for s in steps if s.label == "Обновление")
    assert upd.command.startswith("sudo -S -p '' env DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade")

    # Ключи хостов закреплены при первом подключении (TOFU).
    assert db.scalar(select(HostKey).where(HostKey.host == "10.20.2.21")).pinned_via == "tofu"
    # После раскатки — повторная проверка «Сканером»; 10.20.2.26 «Сканер» проверить не может (нет учётки).
    t = _ticket(db, ASTRA_SSH)
    assert r.verification_ids
    hs = {h.host: h.status for h in t.hosts}
    assert hs["10.20.2.21"] == "confirmed" and hs["10.20.2.26"] == "unverified"
    assert t.status == "fixed"
    actions = {a.action for a in db.scalars(select(AuditLog).where(AuditLog.object_type == "rollout"))}
    assert {
        "rollout.create",
        "rollout.dry_run",
        "rollout.approve",
        "rollout.start",
        "rollout.host",
        "rollout.finish",
    } <= actions


def test_four_eyes_preparer_cannot_approve(client, as_, db, project, sim):
    t = _ticket(db, GLIBC)
    d = client.get(f"/tickets/{t.id}/rollout-draft", headers=as_("lead")).json()
    assert d["manager"] == "dnf" and d["packages"] == ["glibc"]
    r = client.post(
        f"/tickets/{t.id}/rollouts",
        headers=as_("lead"),
        json={k: d[k] for k in ("template", "manager", "packages", "fixed_version")},
    )
    rid = r.json()["id"]
    client.post(f"/rollouts/{rid}/dry-run", headers=as_("lead"))
    ro = client.get(f"/rollouts/{rid}", headers=as_("lead")).json()
    assert ro["status"] == "pending_approval", ro
    assert ro["can"]["approve"] is False
    r = _approve(client, as_, rid, "lead")
    assert r.status_code == 403 and "Четыре глаза" in r.json()["detail"]
    assert _actions(db, "rollout.approve")[-1].result == "denied"
    assert _approve(client, as_, rid, "manager").status_code == 200
    # Утвердивший руководитель не может запустить (нет права), lead — может.
    assert client.post(f"/rollouts/{rid}/start", headers=as_("manager")).status_code == 403
    assert client.post(f"/rollouts/{rid}/start", headers=as_("lead")).status_code == 202
    db.expire_all()
    r = db.get(Rollout, rid)
    assert r.status == "done", r.error
    dnf = [s for s in db.scalars(select(RolloutStep).where(RolloutStep.label == "Пробный прогон"))]
    assert dnf and all("dnf upgrade --assumeno glibc" in s.command and s.ok for s in dnf)  # код 1 — норма для dnf


def test_window_required_and_checked_at_start(client, as_, db, project, sim):
    pid = project
    ro = _prepared(client, as_, db)
    rid = ro["id"]
    r = client.post(f"/rollouts/{rid}/approve", headers=as_("manager"), json={})
    assert r.status_code == 422 and "окна" in r.json()["detail"]
    # Окно в будущем: утвердить можно, запустить — нет (сейчас закрыто).
    start = utcnow() + timedelta(days=2)
    w = client.post(
        f"/projects/{pid}/windows",
        headers=as_("manager"),
        json={
            "name": "Потом",
            "kind": "once",
            "starts_at": start.isoformat(),
            "ends_at": (start + timedelta(hours=2)).isoformat(),
        },
    ).json()
    db.get(Rollout, rid).window_id = w["id"]
    db.commit()
    assert client.post(f"/rollouts/{rid}/approve", headers=as_("manager"), json={}).status_code == 200
    r = client.post(f"/rollouts/{rid}/start", headers=as_("engineer"))
    assert r.status_code == 409 and "закрыто" in r.json()["detail"]
    assert _actions(db, "rollout.start")[-1].result == "denied"
    # Окно открыто сейчас — запускается.
    now = utcnow() - timedelta(minutes=5)
    client.patch(
        f"/windows/{w['id']}",
        headers=as_("manager"),
        json={"starts_at": now.isoformat(), "ends_at": (now + timedelta(hours=2)).isoformat()},
    )
    assert client.post(f"/rollouts/{rid}/start", headers=as_("engineer")).status_code == 202
    db.expire_all()
    assert db.get(Rollout, rid).status == "done"


def test_blackout_blocks_even_outside_window(client, as_, db, project, sim):
    pid = project
    now = utcnow() - timedelta(minutes=5)
    client.post(
        f"/projects/{pid}/windows",
        headers=as_("manager"),
        json={
            "name": "Заморозка",
            "kind": "blackout",
            "starts_at": now.isoformat(),
            "ends_at": (now + timedelta(hours=3)).isoformat(),
        },
    )
    ro = _prepared(client, as_, db)
    assert _approve(client, as_, ro["id"]).status_code == 200
    r = client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    assert r.status_code == 409 and "блэкаут «Заморозка»" in r.json()["detail"]


def test_allowlist_reread_at_start(client, as_, db, project, sim):
    ro = _prepared(client, as_, db)
    rid = ro["id"]
    assert _approve(client, as_, rid).status_code == 200
    mock = MockScanner.shared("demo")
    keep = mock.data["allowlist"]["7"]
    # После утверждения из allowlist убрали 10.20.2.0/24, кроме двух хостов.
    mock.data["allowlist"]["7"] = [{"id": 9, "cidr": "10.20.2.21/32"}, {"id": 10, "cidr": "10.20.2.22/32"}]
    r = client.post(f"/rollouts/{rid}/start", headers=as_("engineer"))
    assert r.status_code == 202
    db.expire_all()
    hs = {h.host: (h.status, h.reason) for h in db.get(Rollout, rid).hosts}
    assert hs["10.20.2.21"][0] == "succeeded" and hs["10.20.2.22"][0] == "succeeded"
    assert hs["10.20.2.23"] == ("skipped", "вне allowlist проекта «Сканера»")
    assert not any(c for c in sim.hosts["10.20.2.23"].commands if "install" in c and "-s" not in c)
    denied = _actions(db, "rollout.denied")
    assert denied and denied[-1].result == "denied" and "10.20.2.23" in denied[-1].details["hosts"]
    # Ни одного хоста в allowlist — запуск отклонён целиком.
    mock.data["allowlist"]["7"] = [{"id": 11, "cidr": "192.0.2.0/24"}]
    ro2 = _prepared(client, as_, db, title=GLIBC)
    assert ro2["status"] == "draft" and "allowlist" in ro2["hosts"][0]["reason"]
    mock.data["allowlist"]["7"] = keep


def test_canary_failure_stops_rollout(client, as_, db, project, sim):
    ro = _prepared(client, as_, db, canary_host="10.20.2.23")
    sim.hosts["10.20.2.23"].fail_upgrade = True
    _approve(client, as_, ro["id"])
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r = db.get(Rollout, ro["id"])
    assert r.status == "failed" and "Канарейка 10.20.2.23" in r.error
    hs = {h.host: h.status for h in r.hosts}
    assert hs["10.20.2.23"] == "failed"
    assert {s for h, s in hs.items() if h != "10.20.2.23"} == {"skipped"}
    assert sim.hosts["10.20.2.21"].packages["openssh-server"].version.endswith("ci202306")
    assert not r.verification_ids


def test_failure_threshold(client, as_, db, project, sim):
    ro = _prepared(client, as_, db, canary_host="10.20.2.21", batch_percent=20, failure_threshold=0)
    sim.hosts["10.20.2.22"].fail_upgrade = True
    _approve(client, as_, ro["id"])
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r = db.get(Rollout, ro["id"])
    assert r.status == "failed" and "Превышен порог ошибок" in r.error
    hs = {h.host: h.status for h in r.hosts}
    assert hs["10.20.2.21"] == "succeeded" and hs["10.20.2.22"] == "failed"
    # 20 % от 6 — партии по 2 хоста: после первой партии (22 — ошибка, 23 — успех) раскатка встала.
    assert hs["10.20.2.23"] == "succeeded" and list(hs.values()).count("skipped") == 3
    # Где изменение прошло — повторная проверка всё равно ставится.
    assert r.verification_ids


def test_emergency_stop(client, as_, db, project, sim, monkeypatch):
    ro = _prepared(client, as_, db, canary_host="10.20.2.21", batch_percent=20)
    _approve(client, as_, ro["id"])
    real = svc._stop_requested

    def fake(db_, rid):  # после канарейки кто-то нажал «Аварийный стоп»
        done = db_.scalar(select(RolloutHost).where(RolloutHost.rollout_id == rid, RolloutHost.status == "succeeded"))
        return done is not None or real(db_, rid)

    monkeypatch.setattr(svc, "_stop_requested", fake)
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r = db.get(Rollout, ro["id"])
    assert r.status == "stopped"
    hs = {h.host: (h.status, h.reason) for h in r.hosts}
    assert hs["10.20.2.21"][0] == "succeeded"
    assert {v for k, v in hs.items() if k != "10.20.2.21"} == {("skipped", "аварийный стоп")}


def test_stop_endpoint_rights(client, as_, db, project, sim):
    ro = _prepared(client, as_, db)
    r = db.get(Rollout, ro["id"])
    r.status = "running"
    db.commit()
    assert client.post(f"/rollouts/{r.id}/stop", headers=as_("viewer"), json={"reason": "стоп!"}).status_code == 403
    r2 = client.post(f"/rollouts/{r.id}/stop", headers=as_("manager"), json={"reason": "Заказчик просит остановить"})
    assert r2.status_code == 200 and r2.json()["stop_requested"] is True
    assert _actions(db, "rollout.stop")[-1].details["reason"] == "Заказчик просит остановить"


def _kernel_ticket(db) -> Ticket:
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.kind == "kernel", Ticket.os == "Debian 12")).one()


def test_kernel_reboot_only_when_allowed(client, as_, db, project, sim):
    t = _kernel_ticket(db)
    d = client.get(f"/tickets/{t.id}/rollout-draft", headers=as_("engineer")).json()
    assert d["template"] == "kernel" and d["packages"] == ["linux-image-amd64"] and d["reboot"] is True
    hosts = ["10.20.1.11", "10.20.1.12"]
    ro = _prepared(client, as_, db, title=t.title, hosts=hosts, canary_host="10.20.1.11")
    assert ro["status"] == "pending_approval", ro
    _approve(client, as_, ro["id"], allow_reboot=False)
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r = db.get(Rollout, ro["id"])
    assert r.status == "done"
    assert {h.status for h in r.hosts} == {"reboot_pending"}
    assert not r.verification_ids  # ядро не загружено — проверять рано
    assert not any(c[-1:] == ["reboot"] for c in sim.hosts["10.20.1.11"].commands)

    # Вторая раскатка с разрешённой перезагрузкой: хост перезагружается, ядро «после» — новое.
    ro2 = _prepared(client, as_, db, title=t.title, hosts=hosts, canary_host="10.20.1.11")
    _approve(client, as_, ro2["id"], allow_reboot=True)
    boot = sim.hosts["10.20.1.11"].boot_id
    client.post(f"/rollouts/{ro2['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r2 = db.get(Rollout, ro2["id"])
    assert r2.status == "done", r2.error
    h = next(x for x in r2.hosts if x.host == "10.20.1.11")
    assert h.status == "succeeded" and h.rebooted and h.reboot_required, h.reason
    assert sim.hosts["10.20.1.11"].boot_id != boot
    assert h.kernel_after == "6.1.106-3-amd64"
    assert r2.verification_ids


def test_reboot_timeout_fails_host(client, as_, db, project, sim):
    t = _kernel_ticket(db)
    ro = _prepared(client, as_, db, title=t.title, hosts=["10.20.1.11"], canary_host="10.20.1.11")
    sim.hosts["10.20.1.11"].reboot_hangs = True
    _approve(client, as_, ro["id"], allow_reboot=True)
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    h = db.get(Rollout, ro["id"]).hosts[0]
    assert h.status == "failed" and "не вернулся после перезагрузки" in h.reason


def test_host_key_change_refuses_host(client, as_, db, project, sim):
    ro = _prepared(client, as_, db, hosts=["10.20.2.21", "10.20.2.22"], canary_host="10.20.2.21")
    _approve(client, as_, ro["id"])
    # Между пробным прогоном и запуском ключ 10.20.2.22 сменился.
    sim.set_key("10.20.2.22", asyncssh.generate_private_key("ssh-ed25519"))
    client.post(f"/rollouts/{ro['id']}/start", headers=as_("engineer"))
    db.expire_all()
    r = db.get(Rollout, ro["id"])
    hs = {h.host: (h.status, h.reason) for h in r.hosts}
    assert hs["10.20.2.22"][0] == "failed" and "Ключ хоста" in hs["10.20.2.22"][1]
    assert db.scalar(select(HostKey).where(HostKey.host == "10.20.2.22")).status == "mismatch"
    assert sim.hosts["10.20.2.22"].packages["openssh-server"].version.endswith("ci202306")


def test_service_and_custom_templates(client, as_, db, project, sim):
    t = _ticket(db, GLIBC)
    r = client.post(
        f"/tickets/{t.id}/rollouts",
        headers=as_("engineer"),
        json={"template": "service", "service": "sshd; reboot"},
    )
    assert r.status_code == 422
    r = client.post(
        f"/tickets/{t.id}/rollouts",
        headers=as_("engineer"),
        json={"template": "service", "service": "sshd", "hosts": ["10.20.3.32"]},
    )
    rid = r.json()["id"]
    client.post(f"/rollouts/{rid}/dry-run", headers=as_("engineer"))
    _approve(client, as_, rid)
    client.post(f"/rollouts/{rid}/start", headers=as_("engineer"))
    db.expire_all()
    ro = db.get(Rollout, rid)
    assert ro.status == "done" and ro.hosts[0].versions_after == {"sshd": "active"}
    assert ["sudo", "-S", "-p", "", "systemctl", "restart", "sshd"] in sim.hosts["10.20.3.32"].commands

    # Произвольная команда: только с custom_commands и отдельным подтверждением при утверждении.
    r = client.post(
        f"/tickets/{t.id}/rollouts",
        headers=as_("lead"),
        json={"template": "custom", "command": "systemctl restart 'crond'; id", "hosts": ["10.20.3.33"]},
    )
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert r.json()["command"] == "systemctl restart crond\\; id" or r.json()["command"].startswith("systemctl restart")
    client.post(f"/rollouts/{rid}/dry-run", headers=as_("lead"))
    r = _approve(client, as_, rid)
    assert r.status_code == 422 and "подтверждения" in r.json()["detail"]
    assert _approve(client, as_, rid, custom_ack=True).status_code == 200
    client.post(f"/rollouts/{rid}/start", headers=as_("engineer"))
    db.expire_all()
    ro = db.get(Rollout, rid)
    # «;» не стал разделителем команд: ушёл аргументом systemctl, служба не нашлась.
    assert ro.status == "failed" and ro.hosts[0].status == "failed"
    assert ["sudo", "-S", "-p", "", "systemctl", "restart", "crond;", "id"] in sim.hosts["10.20.3.33"].commands


def test_one_running_rollout_per_project_and_restart_recovery(client, as_, db, project, sim):
    a = _prepared(client, as_, db)
    b = _prepared(client, as_, db, title=GLIBC)
    _approve(client, as_, a["id"])
    _approve(client, as_, b["id"])
    ra = db.get(Rollout, a["id"])
    ra.status = "running"
    db.commit()
    r = client.post(f"/rollouts/{b['id']}/start", headers=as_("engineer"))
    assert r.status_code == 409 and f"№{a['id']}" in r.json()["detail"]
    # Служба перезапустилась, пока хост раскатки был в работе: хост — ошибка, раскатка остановлена.
    db.expire_all()
    ra = db.get(Rollout, a["id"])
    ra.hosts[0].status, ra.hosts[0].stage = "running", 0
    for h in ra.hosts[1:]:
        h.status, h.stage = "queued", 1
    db.commit()
    svc.execute(db, ra.id)
    db.expire_all()
    ra = db.get(Rollout, a["id"])
    assert ra.status == "failed" and "перезапуском службы" in ra.error
    assert {h.status for h in ra.hosts[1:]} == {"skipped"}


def test_stale_dry_run_and_cancel(client, as_, db, project, sim):
    ro = _prepared(client, as_, db)
    r = db.get(Rollout, ro["id"])
    r.dry_run_at = utcnow() - timedelta(days=8)
    db.commit()
    assert _approve(client, as_, ro["id"]).status_code == 409
    assert client.post(f"/rollouts/{ro['id']}/cancel", headers=as_("viewer"), json={}).status_code == 403
    r = client.post(f"/rollouts/{ro['id']}/cancel", headers=as_("engineer"), json={"reason": "передумали"})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    lst = client.get(f"/projects/{project}/rollouts?active=true", headers=as_("viewer"))
    assert lst.json() == [] and lst.headers["X-Total-Count"] == "0"


def test_parallelism_setting(client, as_, project):
    assert (
        client.put(
            f"/projects/{project}/rollout-settings", headers=as_("engineer"), json={"rollout_parallelism": 3}
        ).status_code
        == 403
    )
    r = client.put(f"/projects/{project}/rollout-settings", headers=as_("manager"), json={"rollout_parallelism": 3})
    assert r.status_code == 200 and r.json() == {"rollout_parallelism": 3}
    assert (
        client.put(
            f"/projects/{project}/rollout-settings", headers=as_("manager"), json={"rollout_parallelism": 0}
        ).status_code
        == 422
    )


# --- устойчивость: сбой задачи не оставляет раскатку «в работе» (задача А ревью 2026-11) ---


def _boom(*_a, **_kw):
    raise RuntimeError("обрыв соединения с БД")


def test_job_crash_gives_rollout_final_status(client, as_, db, project, sim, monkeypatch):
    a = _prepared(client, as_, db)
    b = _prepared(client, as_, db, title=GLIBC)
    _approve(client, as_, a["id"])
    _approve(client, as_, b["id"])
    monkeypatch.setattr(svc, "_parallelism", _boom)
    r = client.post(f"/rollouts/{a['id']}/start", headers=as_("engineer"))
    assert r.status_code == 202, r.text
    db.expire_all()
    ra = db.get(Rollout, a["id"])
    assert db.get(Job, ra.job_id).status == "failed"
    assert ra.status == "failed" and ra.finished_at is not None
    assert "прервана сбоем задачи" in ra.error and "RuntimeError" in ra.error
    assert {h.status for h in ra.hosts} == {"skipped"}
    assert _actions(db, "rollout.finish")[-1].result == "error"
    # Раскатка больше не занимает проект: соседняя стартует.
    monkeypatch.undo()
    monkeypatch.setattr(sshexec, "route", sim.route)
    r = client.post(f"/rollouts/{b['id']}/start", headers=as_("engineer"))
    assert r.status_code == 202, r.text
    assert client.get(f"/rollouts/{b['id']}", headers=as_("engineer")).json()["status"] == "done"


def test_dry_run_job_crash_returns_to_draft(client, as_, db, project, sim, monkeypatch):
    ro = _prepared(client, as_, db)
    monkeypatch.setattr(svc, "check_allowlist", _boom)
    r = client.post(f"/rollouts/{ro['id']}/dry-run", headers=as_("engineer"))
    assert r.status_code == 202, r.text
    out = client.get(f"/rollouts/{ro['id']}", headers=as_("engineer")).json()
    assert out["status"] == "draft" and "Пробный прогон прерван сбоем задачи" in out["error"]
    assert out["can"]["dry_run"] is True
    monkeypatch.undo()
    monkeypatch.setattr(sshexec, "route", sim.route)
    assert client.post(f"/rollouts/{ro['id']}/dry-run", headers=as_("engineer")).status_code == 202
    assert client.get(f"/rollouts/{ro['id']}", headers=as_("engineer")).json()["status"] == "pending_approval"


def test_recover_and_stop_close_rollout_without_live_job(client, as_, db, project, sim):
    """Раскатка «Идёт», а её задача уже failed (зависла до исправления)."""
    a = _prepared(client, as_, db)
    b = _prepared(client, as_, db, title=GLIBC)

    def stuck(rid):
        db.expire_all()
        r = db.get(Rollout, rid)
        r.status = "running"
        r.hosts[0].status, r.hosts[0].stage = "running", 0
        for h in r.hosts[1:]:
            h.status, h.stage = "queued", 1
        job = db.get(Job, r.job_id)
        job.status, job.error = "failed", "Внутренняя ошибка: OperationalError"
        db.commit()

    # Сверка при старте службы.
    stuck(a["id"])
    jobs.runner.recover()
    db.expire_all()
    ra = db.get(Rollout, a["id"])
    assert ra.status == "failed" and "задача завершилась сбоем" in ra.error
    assert ra.hosts[0].status == "failed" and "проверьте хост вручную" in ra.hosts[0].reason
    assert {h.status for h in ra.hosts[1:]} == {"skipped"}
    # Аварийный стоп без перезапуска службы: флаг некому прочитать — раскатка завершается сразу.
    stuck(b["id"])
    r = client.post(f"/rollouts/{b['id']}/stop", headers=as_("manager"), json={"reason": "Раскатка зависла"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "stopped" and out["stop_reason"] == "Раскатка зависла" and out["finished_at"]
    assert out["can"]["stop"] is False
