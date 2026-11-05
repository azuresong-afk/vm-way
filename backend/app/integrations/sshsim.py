"""Демо-стенд SSH: поддельные Linux-хосты для раскаток без живой инфраструктуры (как мок «Сканера»).

Каждый хост — настоящий SSH-сервер asyncssh на 127.0.0.1 со своим ключом хоста. Стенд отвечает на
те команды, которые строит «Устранение» (app/services/rollout_templates.py): `id`, `/etc/os-release`,
sudo, `dpkg-query`/`rpm -q`, `apt-get`/`dnf`/`yum` в пробном и рабочем режиме, флаг перезагрузки,
`boot_id`, `uname -r`, `systemctl`. Пакеты и версии — из демо-фикстуры «Сканера»: установлено то,
что нашёл сканер, в репозитории — исправленная версия. Хосты, недоступные «Сканеру», недоступны и тут.

Обновлённый пакет отмечается в «мире» мока «Сканера» (`MockScanner.patched`) — прицельная проверка
после раскатки подтверждает исправление. Ядро считается исправленным только после перезагрузки.

Включается только на демо-стенде (`VM_DEMO=1`) и в тестах: `sshexec.route` направляет подключения
к хостам стенда на его порты. Стенд принимает любой пароль и ключ и любой пароль sudo.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import shlex
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services import rollout_templates as tpl

FIXTURE = Path(__file__).parent / "scanner" / "fixtures" / "demo.json"
CLOSED_PORT = 9  # discard: на 127.0.0.1 никто не слушает — «соединение отклонено»
KNOWN_SERVICES = {"ssh", "sshd", "nginx", "apache2", "httpd", "postgresql", "cron", "crond", "rsyslog", "named"}


@dataclass
class SimPackage:
    version: str
    repo: str  # версия в репозитории хоста
    source: str = ""  # пакет вендора (как в находке «Сканера»)
    kernel: bool = False


@dataclass
class SimHost:
    address: str
    hostname: str = ""
    os_name: str = "Debian GNU/Linux 12 (bookworm)"
    manager: str = "apt"
    packages: dict[str, SimPackage] = field(default_factory=dict)
    reachable: bool = True
    kernel: str = "6.1.0-21-amd64"
    boot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    reboot_required: bool = False
    pending_kernel: str = ""
    services: dict[str, str] = field(default_factory=lambda: {s: "active" for s in KNOWN_SERVICES})
    fail_upgrade: bool = False  # менеджер пакетов падает (сломанный dpkg)
    reboot_hangs: bool = False  # после перезагрузки хост не возвращается
    commands: list[list[str]] = field(default_factory=list)


def host_key(secret: str, host: str) -> asyncssh.SSHKey:
    """Ключ хоста стенда, одинаковый между перезапусками (Ed25519 из HMAC секрета и адреса)."""
    seed = hmac.new(secret.encode(), f"vm-demo-ssh:{host}".encode(), hashlib.sha256).digest()
    pem = Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    return asyncssh.import_private_key(pem)


class SshSim:
    def __init__(
        self,
        hosts: dict[str, SimHost],
        secret: str = "vm-test",  # noqa: S107 — не пароль, соль ключей хостов стенда
        *,
        delay: float = 0.0,
        on_patched: Callable[[str, str], None] | None = None,
    ):
        self.hosts = hosts
        self.secret = secret
        self.delay = delay
        self.on_patched = on_patched
        self._keys: dict[str, asyncssh.SSHKey] = {}
        self._listeners: dict[str, asyncssh.SSHAcceptor] = {}
        self._lock = threading.Lock()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="vm-sshsim", daemon=True)
        self.thread.start()

    # --- ключи и адреса ---
    def key(self, host: str) -> asyncssh.SSHKey:
        if host not in self._keys:
            self._keys[host] = host_key(self.secret, host)
        return self._keys[host]

    def set_key(self, host: str, key: asyncssh.SSHKey) -> None:
        """Сменить ключ хоста (тест «ключ изменился»)."""
        self._keys[host] = key
        with self._lock:
            lst = self._listeners.get(host)
        if lst is not None:
            lst.update(server_host_keys=[key])

    def public_key(self, host: str) -> tuple[str, str, str]:
        k = self.key(host)
        return k.get_algorithm(), k.get_fingerprint("sha256"), " ".join(k.export_public_key().decode().split()[:2])

    def route(self, host: str, port: int) -> tuple[str, int]:
        h = self.hosts.get(host)
        if h is None:
            return host, port
        if not h.reachable:
            return "127.0.0.1", CLOSED_PORT
        with self._lock:
            lst = self._listeners.get(host)
            if lst is None:
                lst = self._call(self._listen(host))
                self._listeners[host] = lst
        return "127.0.0.1", lst.sockets[0].getsockname()[1]

    def _call(self, coro):  # noqa: ANN001, ANN202
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(15)

    async def _listen(self, host: str) -> asyncssh.SSHAcceptor:
        return await asyncssh.listen(
            "127.0.0.1",
            0,
            server_host_keys=[self.key(host)],
            server_factory=_Server,
            process_factory=lambda p: self._process(host, p),
            encoding="utf-8",
        )

    def close(self) -> None:
        with self._lock:
            listeners = list(self._listeners.values())
            self._listeners.clear()
        for lst in listeners:
            lst.close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    # --- команды ---
    async def _sleep(self, k: float) -> None:
        if self.delay:
            await asyncio.sleep(self.delay * k)

    async def _process(self, address: str, process: asyncssh.SSHServerProcess) -> None:
        h = self.hosts[address]
        user = process.get_extra_info("username")
        try:
            argv = shlex.split(process.command or "")
        except ValueError:
            argv = []
        h.commands.append(argv)
        root = user == "root"
        if argv[:1] == ["sudo"]:
            if argv[1:3] == ["-S", "-k"] or argv[1:2] == ["-S"]:
                await process.stdin.readline()  # пароль sudo: стенд принимает любой
                rest = argv[1:]
                while rest and rest[0] in ("-S", "-k", "-n"):
                    rest = rest[1:]
                if rest[:2] == ["-p", ""]:
                    rest = rest[2:]
            else:
                rest = [a for a in argv[1:] if a != "-n"]
            argv, root = rest, True
        if argv[:1] == ["env"]:
            argv = argv[1:]
            while argv and re.match(r"^[A-Z_]+=", argv[0]):
                argv = argv[1:]
        out, err, code = await self._exec(h, user, root, argv)
        if out:
            process.stdout.write(out)
        if err:
            process.stderr.write(err)
        process.exit(code)

    async def _exec(self, h: SimHost, user: str, root: bool, argv: list[str]) -> tuple[str, str, int]:
        cmd = argv[0] if argv else ""
        if argv == ["id", "-un"]:
            return f"{user}\n", "", 0
        if argv == ["id", "-u"]:
            return ("0\n" if user == "root" else "1000\n"), "", 0
        if argv == ["true"]:
            return "", "", 0
        if argv == ["cat", "/etc/os-release"]:
            return f'PRETTY_NAME="{h.os_name}"\n', "", 0
        if argv == tpl.BOOT_ID_CMD:
            return h.boot_id + "\n", "", 0
        if argv == tpl.KERNEL_CMD:
            return h.kernel + "\n", "", 0
        if argv == ["test", "-e", "/var/run/reboot-required"]:
            return "", "", 0 if h.reboot_required else 1
        if argv == ["needs-restarting", "-r"]:
            if h.reboot_required:
                return "Reboot is required to fully utilize these updates.\n", "", 1
            return "No core libraries or services have been updated since boot-up.\n", "", 0
        if cmd == "dpkg-query" and h.manager == "apt":
            return self._query(h, argv[3:], "{p}\t{v}\n", "dpkg-query: no packages found matching {p}\n")
        if cmd == "rpm" and argv[1:2] == ["-q"]:
            return self._query(h, argv[4:], "{p}\t(none):{v}\n", "package {p} is not installed\n")
        if cmd in ("apt-get", "dnf", "yum"):
            return await self._pkg(h, root, argv)
        if cmd == "systemctl":
            return await self._systemctl(h, root, argv)
        return "", f"sh: 1: {cmd}: not found\n", 127

    def _query(self, h: SimHost, pkgs: list[str], ok: str, missing: str) -> tuple[str, str, int]:
        out, err = [], []
        for p in pkgs:
            if p in h.packages:
                out.append(ok.format(p=p, v=h.packages[p].version))
            else:
                err.append(missing.format(p=p))
        return "".join(out), "".join(err), 0 if not err else 1

    def _upgradable(self, h: SimHost, pkgs: list[str]) -> list[tuple[str, SimPackage]]:
        out = []
        for p in pkgs:
            sp = h.packages.get(p)
            if sp and tpl.compare(h.manager, sp.repo, sp.version) > 0:
                out.append((p, sp))
        return out

    async def _pkg(self, h: SimHost, root: bool, argv: list[str]) -> tuple[str, str, int]:
        cmd = argv[0]
        if (cmd == "apt-get") != (h.manager in ("apt", "apt-rpm")):
            return "", f"sh: 1: {cmd}: not found\n", 127
        simulate = "-s" in argv or "--assumeno" in argv
        if not root and not simulate:
            if cmd == "apt-get":
                return (
                    "",
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n",
                    100,
                )
            return "", "Error: This command has to be run with superuser privileges.\n", 1
        if argv[1:2] == ["update"]:
            await self._sleep(1)
            return "Hit:1 http://deb.debian.org/debian bookworm InRelease\nReading package lists...\n", "", 0
        pkgs = [a for a in argv[1:] if not a.startswith("-") and a not in ("install", "upgrade", "update")]
        pkgs = [a for a in pkgs if not a.startswith("Dpkg::")]
        todo = self._upgradable(h, pkgs)
        if cmd == "apt-get":
            lines = [f"Inst {p} [{sp.version}] ({sp.repo} Demo:stable [amd64])" for p, sp in todo]
            if simulate:
                head = "Reading package lists...\nBuilding dependency tree...\n"
                tail = f"{len(todo)} upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                return head + "\n".join(lines) + ("\n" if lines else "") + tail, "", 0
        else:
            rows = "".join(f" {p:<20} x86_64   {sp.repo:<24} demo   1.2 M\n" for p, sp in todo)
            if simulate:
                if not todo:
                    return "Dependencies resolved.\nNothing to do.\nComplete!\n", "", 0
                return f"Dependencies resolved.\nUpgrading:\n{rows}\nOperation aborted.\n", "", 1
        await self._sleep(3)
        if h.fail_upgrade:
            return "", "E: Sub-process /usr/bin/dpkg returned an error code (1)\n", 100 if cmd == "apt-get" else 1
        body = "".join(
            f"Unpacking {p} ({sp.repo}) over ({sp.version}) ...\nSetting up {p} ({sp.repo}) ...\n" for p, sp in todo
        )
        for _p, sp in todo:
            sp.version = sp.repo
            if sp.kernel:
                h.reboot_required = True
                h.pending_kernel = sp.repo + ("-amd64" if h.manager == "apt" else ".x86_64")
            elif self.on_patched and sp.source:
                self.on_patched(h.address, sp.source)
        if cmd == "apt-get":
            return f"Reading package lists...\n{body}{len(todo)} upgraded, 0 newly installed.\n", "", 0
        return f"Upgrading:\n{rows}\nComplete!\n", "", 0

    async def _systemctl(self, h: SimHost, root: bool, argv: list[str]) -> tuple[str, str, int]:
        if argv[1:] == ["reboot"]:
            if not root:
                return "", "Failed to set wall message: Interactive authentication required.\n", 1
            asyncio.get_running_loop().call_later(max(self.delay * 5, 0.05), self._reboot, h)
            return "", "", 0
        if len(argv) == 4 and argv[1] == "show":
            unit = argv[3]
            state = h.services.get(unit.removesuffix(".service"))
            if state is None:
                return "LoadState=not-found\nActiveState=inactive\n", "", 0
            return f"LoadState=loaded\nActiveState={state}\n", "", 0
        if len(argv) == 3 and argv[1] in ("restart", "is-active"):
            unit = argv[2].removesuffix(".service")
            if unit not in h.services:
                return "", f"Failed to {argv[1]} {argv[2]}: Unit {argv[2]} not found.\n", 5
            if argv[1] == "is-active":
                return h.services[unit] + "\n", "", 0 if h.services[unit] == "active" else 3
            if not root:
                return "", "Failed to restart: Access denied\n", 1
            await self._sleep(1)
            h.services[unit] = "active"
            return "", "", 0
        return "", "Unknown command verb.\n", 1

    def _reboot(self, h: SimHost) -> None:
        if h.reboot_hangs:
            h.reachable = False
            return
        h.boot_id = str(uuid.uuid4())
        if h.pending_kernel:
            h.kernel, h.pending_kernel = h.pending_kernel, ""
            if self.on_patched:
                for sp in h.packages.values():
                    if sp.kernel and sp.source:
                        self.on_patched(h.address, sp.source)
        h.reboot_required = False

    # --- демо ---
    @classmethod
    def from_fixture(cls, secret: str, *, delay: float = 0.5, on_patched=None) -> SshSim:  # noqa: ANN001
        """Хосты демо-фикстуры «Сканера»: ОС, установленные и исправленные версии пакетов."""
        from app.integrations.scanner.mock import vendor_package

        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        base = next(r for r in data["runs"] if r["run"]["id"] == data["world"]["base_run_id"])
        findings = {f["id"]: f for f in base["findings"]}
        patched = {(p["host"], p["package"]) for p in data["world"].get("patched", [])}
        unreachable = set(data["world"].get("unreachable", []))
        hosts: dict[str, SimHost] = {}
        for h in data["hosts"]:
            manager = tpl.default_manager(h.get("os_family", ""), None) or "apt"
            hosts[h["address"]] = SimHost(
                address=h["address"],
                hostname=h.get("hostname", ""),
                os_name=h.get("os_guess") or "Linux",
                manager=manager,
                reachable=h["address"] not in unreachable,
                kernel="6.1.0-21-amd64" if manager == "apt" else "6.1.20-1.el7.x86_64",
            )
        for fx in base["fixes"]:
            if fx["kind"] not in ("package", "package_upgrade", "package_nofix", "kernel"):
                continue
            for fh in fx["hosts"]:
                sh = hosts.get(fh["host"])
                if sh is None:
                    continue
                refs = [findings[r["id"]] for r in fh["findings"] if r["id"] in findings]
                source = next((s for s in (vendor_package(f) for f in refs) if s), "")
                kernel = fx["kind"] == "kernel"
                names = tpl.KERNEL_PACKAGES.get(sh.manager, ["kernel"]) if kernel else fx.get("packages") or []
                installed = fh.get("installed") or "0"
                if kernel:
                    sh.kernel = installed
                fixed = fx.get("fixed_version") or installed
                done = (sh.address, source) in patched
                for name in names:
                    sh.packages[name] = SimPackage(
                        version=fixed if done else installed,
                        repo=installed if fx["kind"] == "package_nofix" else fixed,
                        source=source,
                        kernel=kernel,
                    )
        return cls(hosts, secret, delay=delay, on_patched=on_patched)


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return bool(password)

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return True


_demo: SshSim | None = None


def demo() -> SshSim | None:
    return _demo


def start_demo(secret: str) -> SshSim:
    """Стенд демо: подключения к хостам фикстуры идут на него; исправления видит мок «Сканера»."""
    global _demo
    from app.integrations.scanner import MockScanner
    from app.services import sshexec

    if _demo is None:
        _demo = SshSim.from_fixture(
            secret, on_patched=lambda host, pkg: MockScanner.shared("demo").patched.add((host, pkg))
        )
        sshexec.route = _demo.route
    return _demo
