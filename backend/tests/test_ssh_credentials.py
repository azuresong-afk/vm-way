"""SSH-учётки и закрепление ключей хостов (задача 2.3) — на настоящем SSH-сервере asyncssh в процессе."""

import asyncio
import json
import shlex
import socket
import threading

import asyncssh
import pytest
from sqlalchemy import select

from app.models import Asset, AssetGroup, AuditLog, HostKey, Project, SshCredential
from app.services import credentials as svc
from app.services import sshexec

PASSWORD = "S3cret-login-pass"
SUDO_PASSWORD = "S3cret-sudo-pass"


class SshServer:
    """SSH-сервер в отдельном потоке: пароль и ключи, `id`, `/etc/os-release`, sudo."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.users: dict[str, dict] = {
            "deploy": {"password": PASSWORD, "sudo": PASSWORD, "uid": 1000, "keys": []},
            "keyuser": {"password": None, "sudo": SUDO_PASSWORD, "uid": 1001, "keys": [], "nopasswd": False},
            "root": {"password": PASSWORD, "uid": 0, "keys": []},
        }
        self.auth_attempts: list[tuple[str, str]] = []
        self.connections = 0
        self.commands: list[list[str]] = []

        async def _listen():
            return await asyncssh.listen(
                "127.0.0.1",
                0,
                server_host_keys=[self.host_key],
                server_factory=lambda: _Srv(self),
                process_factory=self._process,
                encoding="utf-8",
            )

        self.listener = self.call(_listen())
        self.port = self.listener.sockets[0].getsockname()[1]

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(15)

    def set_host_key(self, key) -> None:
        self.host_key = key
        self.listener.update(server_host_keys=[key])

    async def _process(self, process: asyncssh.SSHServerProcess) -> None:
        argv = shlex.split(process.command or "")
        self.commands.append(argv)
        u = self.users[process.get_extra_info("username")]
        code = 0
        if argv == ["id", "-un"]:
            process.stdout.write(process.get_extra_info("username") + "\n")
        elif argv == ["id", "-u"]:
            process.stdout.write(f"{u['uid']}\n")
        elif argv == ["cat", "/etc/os-release"]:
            process.stdout.write('NAME="Debian GNU/Linux"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
        elif argv == ["sudo", "-S", "-k", "-p", "", "true"]:
            line = await process.stdin.readline()
            code = 0 if line.rstrip("\n") == u.get("sudo") else 1
        elif argv == ["sudo", "-n", "true"]:
            code = 0 if u.get("nopasswd") else 1
        else:
            code = 127
        process.exit(code)

    def close(self) -> None:
        self.listener.close()
        self.call(self.listener.wait_closed())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class _Srv(asyncssh.SSHServer):
    def __init__(self, st: SshServer):
        self.st = st

    def connection_made(self, conn) -> None:
        self.st.connections += 1

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.st.auth_attempts.append((username, "password"))
        u = self.st.users.get(username)
        return bool(u and u["password"] and u["password"] == password)

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key) -> bool:
        self.st.auth_attempts.append((username, "publickey"))
        u = self.st.users.get(username)
        return bool(u and any(k.public_data == key.public_data for k in u["keys"]))


@pytest.fixture()
def ssh_server():
    s = SshServer()
    yield s
    s.close()


@pytest.fixture()
def project(db, users):
    pr = Project(name="Тест SSH")
    db.add(pr)
    db.flush()
    dmz = AssetGroup(project_id=pr.id, name="DMZ")
    db.add(dmz)
    db.add(Asset(project_id=pr.id, engagement_id=1, scanner_asset_id=1, address="127.0.0.1", hostname="srv-local"))
    web = Asset(project_id=pr.id, engagement_id=1, scanner_asset_id=2, address="10.0.5.7", hostname="web-07")
    web.groups.append(dmz)
    db.add(web)
    db.commit()
    return pr.id


def _create(client, h, pid, **kw) -> dict:
    body = {"name": "deploy", "username": "deploy", "auth": "password", "password": PASSWORD} | kw
    r = client.post(f"/projects/{pid}/ssh-credentials", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def _check(client, h, cid, host="127.0.0.1") -> dict:
    r = client.post(f"/ssh-credentials/{cid}/check", json={"host": host}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _audit(db, action: str) -> list[AuditLog]:
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


# ---------- учётки ----------


def test_secrets_are_encrypted_and_never_returned(client, as_, db, project):
    h = as_("manager")
    c = _create(client, h, project, become_password=SUDO_PASSWORD, hosts=["10.0.0.0/8", " 127.0.0.1 "])
    assert c["has_secret"] and c["has_become_password"]
    assert c["hosts"] == ["10.0.0.0/8", "127.0.0.1"]
    assert "password" not in c and PASSWORD not in json.dumps(c)
    row = db.get(SshCredential, c["id"])
    assert row.secret_enc.startswith("v1:") and PASSWORD not in row.secret_enc
    assert svc.read_secrets(row) == {"password": PASSWORD, "become_password": SUDO_PASSWORD}
    # Зашифровано с привязкой к id: секрет, переставленный в другую учётку, не читается.
    other = _create(client, h, project, name="other")
    db.get(SshCredential, other["id"]).secret_enc = row.secret_enc
    with pytest.raises(Exception):  # noqa: B017
        svc.read_secrets(db.get(SshCredential, other["id"]))
    db.rollback()
    listing = client.get(f"/projects/{project}/ssh-credentials", headers=as_("viewer"))
    assert listing.status_code == 200 and len(listing.json()) == 2
    assert PASSWORD not in listing.text and SUDO_PASSWORD not in listing.text
    for e in _audit(db, "ssh_credential.create"):
        assert PASSWORD not in json.dumps(e.details) and SUDO_PASSWORD not in json.dumps(e.details)


def test_only_manager_manages_credentials(client, as_, project):
    body = {"name": "x", "username": "deploy", "auth": "password", "password": PASSWORD}
    for who in ("engineer", "viewer", "admin"):
        r = client.post(f"/projects/{project}/ssh-credentials", json=body, headers=as_(who))
        assert r.status_code == 403, who
    c = _create(client, as_("manager"), project)
    assert (
        client.post(
            f"/ssh-credentials/{c['id']}/check", json={"host": "127.0.0.1"}, headers=as_("engineer")
        ).status_code
        == 403
    )
    assert client.delete(f"/ssh-credentials/{c['id']}", headers=as_("viewer")).status_code == 403


def test_validation(client, as_, project):
    h = as_("manager")
    url = f"/projects/{project}/ssh-credentials"
    base = {"name": "x", "username": "deploy", "auth": "password"}
    assert client.post(url, json=base, headers=h).status_code == 422  # нет пароля
    assert client.post(url, json=base | {"password": "p", "username": "bad user"}, headers=h).status_code == 422
    assert client.post(url, json=base | {"password": "p", "hosts": ["10.0.0.0/33"]}, headers=h).status_code == 422
    assert client.post(url, json=base | {"password": "p", "hosts": ["a b"]}, headers=h).status_code == 422
    r = client.post(url, json=base | {"auth": "key", "private_key": "-----BEGIN junk-----"}, headers=h)
    assert r.status_code == 422 and "закрытый ключ" in r.json()["detail"]
    _create(client, h, project, name="dup")
    assert client.post(url, json=base | {"name": "dup", "password": "p"}, headers=h).status_code == 409


def test_key_credential_with_passphrase(client, as_, project):
    h = as_("manager")
    key = asyncssh.generate_private_key("ssh-ed25519")
    pem = key.export_private_key("openssh", passphrase="phrase-123").decode()
    url = f"/projects/{project}/ssh-credentials"
    body = {"name": "k", "username": "keyuser", "auth": "key", "private_key": pem}
    r = client.post(url, json=body, headers=h)
    assert r.status_code == 422 and "парольную фразу" in r.json()["detail"]
    r = client.post(url, json=body | {"passphrase": "wrong"}, headers=h)
    assert r.status_code == 422 and "Неверная" in r.json()["detail"]
    c = client.post(url, json=body | {"passphrase": "phrase-123"}, headers=h).json()
    assert c["key_type"] == "ssh-ed25519"
    assert c["key_fingerprint"] == key.get_fingerprint("sha256")
    assert "BEGIN" not in json.dumps(c)


def test_update_replaces_secrets_and_logs_names_only(client, as_, db, project):
    h = as_("manager")
    c = _create(client, h, project, become_password=SUDO_PASSWORD)
    r = client.patch(f"/ssh-credentials/{c['id']}", json={"password": "N3w-pass", "port": 2222}, headers=h)
    assert r.status_code == 200 and r.json()["port"] == 2222
    assert svc.read_secrets(db.get(SshCredential, c["id"]))["password"] == "N3w-pass"
    # Пустая строка — «не менять».
    client.patch(f"/ssh-credentials/{c['id']}", json={"password": ""}, headers=h)
    db.expire_all()
    assert svc.read_secrets(db.get(SshCredential, c["id"]))["password"] == "N3w-pass"
    # Смена способа входа без ключа — отказ, учётка не меняется.
    r = client.patch(f"/ssh-credentials/{c['id']}", json={"auth": "key"}, headers=h)
    assert r.status_code == 422
    r = client.patch(f"/ssh-credentials/{c['id']}", json={"clear_become_password": True}, headers=h)
    assert r.json()["has_become_password"] is False and r.json()["auth"] == "password"
    entries = _audit(db, "ssh_credential.update")
    assert entries[0].details["secrets_replaced"] == ["password"]
    assert entries[0].details["changes"]["port"] == {"from": 22, "to": 2222}
    assert "N3w-pass" not in json.dumps([e.details for e in entries])
    assert entries[-1].details["secrets_replaced"] == ["become_password_cleared"]


# ---------- выбор учётки для хоста ----------


def _cred(id_: int, hosts=(), groups=(), active=True) -> SshCredential:
    return SshCredential(id=id_, name=f"c{id_}", hosts=list(hosts), groups=list(groups), is_active=active)


def test_resolve_prefers_most_specific():
    everything = _cred(1)
    wide = _cred(2, hosts=["10.0.0.0/8"])
    narrow = _cred(3, hosts=["10.0.5.0/24"])
    dmz = _cred(4, groups=["DMZ"])
    exact = _cred(5, hosts=["10.0.5.7"])
    creds = [everything, wide, narrow, dmz, exact]
    assert svc.resolve(creds, "10.0.5.7", {"DMZ"}).credential is exact
    assert svc.resolve(creds[:4], "10.0.5.7", {"DMZ"}).why == "group"
    m = svc.resolve(creds[:3], "10.0.5.7", set())
    assert m.credential is narrow and m.detail == "10.0.5.0/24"
    assert svc.resolve(creds[:3], "10.9.9.9", set()).credential is wide
    assert svc.resolve(creds[:3], "192.168.1.1", set()).why == "all"
    assert svc.resolve([wide, narrow], "192.168.1.1", set()) is None
    assert (
        svc.resolve([_cred(6, hosts=["10.0.5.7"], active=False), everything], "10.0.5.7", set()).credential
        is everything
    )
    # При равенстве — созданная раньше.
    assert svc.resolve([_cred(8), _cred(7)], "h", set()).credential.id == 7


def test_hosts_overview(client, as_, db, project):
    h = as_("manager")
    _create(client, h, project, name="all")
    dmz = _create(client, h, project, name="dmz", groups=["DMZ"])
    rows = {r["host"]: r for r in client.get(f"/projects/{project}/ssh-hosts", headers=as_("viewer")).json()}
    assert list(rows) == ["10.0.5.7", "127.0.0.1"]
    assert rows["10.0.5.7"]["credential"]["id"] == dmz["id"] and rows["10.0.5.7"]["credential"]["why"] == "group"
    assert rows["127.0.0.1"]["credential"]["name"] == "all" and rows["127.0.0.1"]["keys"] == []
    assert svc.credential_for_host(db, project, "10.0.5.7").credential.name == "dmz"


# ---------- проверка входа и TOFU ----------


def test_check_pins_key_then_detects_change_before_login(client, as_, db, project, ssh_server):
    h = as_("manager")
    c = _create(client, h, project, port=ssh_server.port)
    first = _check(client, h, c["id"])
    assert first["result"] == "ok", first
    assert first["key_state"] == "new"
    assert first["facts"] == {"user": "deploy", "uid": 1000, "os": "Debian GNU/Linux 12 (bookworm)", "become": "sudo"}
    fp = ssh_server.host_key.get_fingerprint("sha256")
    assert first["host_key"]["fingerprint"] == fp and first["host_key"]["pinned_via"] == "tofu"
    assert len(_audit(db, "host_key.pin")) == 1

    second = _check(client, h, c["id"])
    assert second["result"] == "ok" and second["key_state"] == "pinned"
    assert len(_audit(db, "host_key.pin")) == 1

    # Сервер «подменили»: другой ключ того же типа. Отказ до входа — пароль не отправлен.
    attempts = len(ssh_server.auth_attempts)
    new_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh_server.set_host_key(new_key)
    third = _check(client, h, c["id"])
    assert third["result"] == "host_key_mismatch" and third["ok"] is False
    assert len(ssh_server.auth_attempts) == attempts
    hk = db.scalar(select(HostKey))
    db.refresh(hk)
    assert hk.status == "mismatch" and hk.fingerprint == fp
    assert hk.mismatch_fingerprint == new_key.get_fingerprint("sha256") and hk.mismatch_count == 1
    mm = _audit(db, "host_key.mismatch")
    assert len(mm) == 1 and mm[0].result == "denied" and mm[0].details["offered"] == hk.mismatch_fingerprint
    assert db.get(SshCredential, c["id"]).last_check_result == "host_key_mismatch"

    # Пока руководитель не решил — к хосту даже не подключаемся.
    conns = ssh_server.connections
    assert _check(client, h, c["id"])["result"] == "host_key_mismatch"
    assert ssh_server.connections == conns

    row = next(r for r in client.get(f"/projects/{project}/ssh-hosts", headers=h).json() if r["host"] == "127.0.0.1")
    assert row["keys"][0]["status"] == "mismatch" and row["keys"][0]["mismatch"]["fingerprint"]

    # Принять новый ключ — только руководитель и с причиной.
    url = f"/host-keys/{hk.id}/accept"
    assert client.post(url, json={"reason": "хост переустановлен"}, headers=as_("engineer")).status_code == 403
    assert client.post(url, json={"reason": ""}, headers=h).status_code == 422
    r = client.post(url, json={"reason": "хост переустановлен, заявка 1234"}, headers=h)
    assert r.status_code == 200 and r.json()["fingerprint"] == new_key.get_fingerprint("sha256")
    assert r.json()["pinned_via"] == "accepted" and r.json()["status"] == "pinned"
    assert _audit(db, "host_key.accept")[0].details["reason"] == "хост переустановлен, заявка 1234"
    assert _check(client, h, c["id"])["result"] == "ok"
    assert client.post(url, json={"reason": "ещё раз"}, headers=h).status_code == 409


def test_reset_pins_again_on_next_connect(client, as_, db, project, ssh_server):
    h = as_("manager")
    c = _create(client, h, project, port=ssh_server.port)
    _check(client, h, c["id"])
    ssh_server.set_host_key(asyncssh.generate_private_key("ecdsa-sha2-nistp256"))
    # Закреплён ed25519, сервер его больше не предлагает — тоже несовпадение.
    assert _check(client, h, c["id"])["result"] == "host_key_mismatch"
    hk = db.scalar(select(HostKey))
    old_fp = hk.fingerprint
    r = client.post(f"/host-keys/{hk.id}/reset", json={"reason": "сменили ключи по регламенту"}, headers=h)
    assert r.status_code == 204
    again = _check(client, h, c["id"])
    assert again["result"] == "ok" and again["key_state"] == "new"
    assert again["host_key"]["key_type"] == "ecdsa-sha2-nistp256"
    assert [e.details["fingerprint"] for e in _audit(db, "host_key.reset")] == [old_fp]


def test_key_auth_and_sudo(client, as_, project, ssh_server):
    h = as_("manager")
    key = asyncssh.generate_private_key("ssh-ed25519")
    ssh_server.users["keyuser"]["keys"].append(key)
    pem = key.export_private_key("openssh").decode()
    c = _create(client, h, project, name="k", username="keyuser", auth="key", private_key=pem, port=ssh_server.port)
    r = _check(client, h, c["id"])
    # Вход по ключу без пароля sudo — нужен NOPASSWD, его нет.
    assert r["result"] == "become_failed" and "NOPASSWD" in r["message"]
    assert r["host_key"] is not None  # вход был — ключ хоста закреплён
    client.patch(f"/ssh-credentials/{c['id']}", json={"become_password": SUDO_PASSWORD}, headers=h)
    assert _check(client, h, c["id"])["facts"]["become"] == "sudo"
    client.patch(f"/ssh-credentials/{c['id']}", json={"become": "none"}, headers=h)
    assert _check(client, h, c["id"])["facts"]["become"] == "none"
    root = _create(client, h, project, name="root", username="root", port=ssh_server.port)
    assert _check(client, h, root["id"])["facts"]["become"] == "root"


def test_auth_failure_and_unreachable(client, as_, db, project, ssh_server):
    h = as_("manager")
    c = _create(client, h, project, password="wrong-pass", port=ssh_server.port)
    r = _check(client, h, c["id"])
    assert r["result"] == "auth_failed" and r["host_key"] is None
    entry = _audit(db, "ssh_credential.check")[-1]
    assert entry.result == "error" and entry.details["result"] == "auth_failed"
    assert "wrong-pass" not in json.dumps(entry.details)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    c2 = _create(client, h, project, name="closed", port=free_port)
    assert _check(client, h, c2["id"])["result"] == "unreachable"


def test_check_only_project_hosts_in_scope(client, as_, project):
    h = as_("manager")
    c = _create(client, h, project, groups=["DMZ"])
    r = client.post(f"/ssh-credentials/{c['id']}/check", json={"host": "8.8.8.8"}, headers=h)
    assert r.status_code == 422 and "не из этого проекта" in r.json()["detail"]
    r = client.post(f"/ssh-credentials/{c['id']}/check", json={"host": "127.0.0.1"}, headers=h)
    assert r.status_code == 422 and "вне охвата" in r.json()["detail"]


def test_login_repr_hides_secrets():
    login = sshexec.Login(username="u", auth="password", password="p@ss", become_password="s@do")
    assert "p@ss" not in repr(login) and "s@do" not in repr(login)
