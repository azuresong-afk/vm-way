"""SSH-исполнение на asyncssh с закреплением ключа хоста (задача 2.3).

Модуль не знает о БД: закреплённый ключ передаёт вызывающий (`app.services.credentials`), он же
сохраняет ключ, увиденный при первом подключении. Правила — как `StrictHostKeyChecking=accept-new`:

- ключ закреплён — принимается только он; asyncssh согласует с сервером именно его тип ключа, и
  другой ключ отвергается **до входа**: пароль и подпись ключом подменённому серверу не уходят;
- ключа нет — первое подключение принимает ключ сервера (TOFU), вызывающий его закрепляет;
- сервер не предлагает закреплённый тип ключа — тоже несовпадение.

Почему не системный `ssh` и не paramiko: asyncssh берёт пароль и ключ из памяти процесса (на диск
и в argv они не попадают), не читает `~/.ssh` (`config`, ключи, агент, known_hosts отключены явно)
и асинхронен — раскатка (2.4) ведёт партии хостов параллельно в одном потоке. Команды задаются
списком аргументов и экранируются `shlex.join`; пароль для `sudo -S` уходит в stdin канала.
"""

from __future__ import annotations

import asyncio
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import asyncssh

CONNECT_TIMEOUT = 15.0
COMMAND_TIMEOUT = 30.0
MAX_OUTPUT = 64 * 1024

# Коды исхода подключения (они же — `last_check_result` учётки).
OK = "ok"
UNREACHABLE = "unreachable"
TIMEOUT = "timeout"
AUTH_FAILED = "auth_failed"
HOST_KEY_MISMATCH = "host_key_mismatch"
BECOME_FAILED = "become_failed"
ERROR = "error"

# Куда на самом деле подключаться: (адрес, порт) → (адрес, порт). Подменяет только демо-стенд
# (app/integrations/sshsim.py, VM_DEMO=1) и тесты; в рабочем режиме — None.
route: Callable[[str, int], tuple[str, int]] | None = None

RESULT_LABELS = {
    OK: "Вход выполнен",
    UNREACHABLE: "Хост недоступен",
    TIMEOUT: "Таймаут",
    AUTH_FAILED: "Учётные данные отклонены",
    HOST_KEY_MISMATCH: "Ключ хоста не совпал",
    BECOME_FAILED: "sudo не сработал",
    ERROR: "Ошибка",
}


@dataclass(frozen=True)
class HostKeyInfo:
    key_type: str
    fingerprint: str  # SHA256:… как у OpenSSH
    public_key: str  # «тип base64», одна строка known_hosts без адреса

    @classmethod
    def from_key(cls, key: asyncssh.SSHKey) -> HostKeyInfo:
        line = key.export_public_key("openssh").decode().split()
        return cls(
            key_type=key.get_algorithm(), fingerprint=key.get_fingerprint("sha256"), public_key=" ".join(line[:2])
        )


@dataclass
class Login:
    """Учётные данные для входа. Секреты не попадают в repr (и, значит, в логи)."""

    username: str
    auth: str  # password | key
    become: str = "sudo"  # sudo | none
    password: str | None = field(default=None, repr=False)
    private_key: str | None = field(default=None, repr=False)
    passphrase: str | None = field(default=None, repr=False)
    become_password: str | None = field(default=None, repr=False)

    @property
    def sudo_password(self) -> str | None:
        """Пароль для sudo: отдельный, иначе пароль входа (у входа по ключу — нет, нужен NOPASSWD)."""
        return self.become_password or (self.password if self.auth == "password" else None)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False


@dataclass
class CheckOutcome:
    """Итог проверки входа: ключ хоста виден всегда, когда дошло до обмена ключами."""

    code: str
    message: str
    key: HostKeyInfo | None = None
    facts: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.code == OK


class SshFailure(Exception):
    def __init__(self, code: str, message: str, offered: HostKeyInfo | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.offered = offered


def import_private_key(text: str, passphrase: str | None = None) -> asyncssh.SSHKey:
    """Закрытый ключ OpenSSH/PEM/PKCS#8. ValueError с понятной причиной на мусоре."""
    try:
        return asyncssh.import_private_key(text.strip() + "\n", passphrase or None)
    except asyncssh.KeyEncryptionError:
        raise ValueError("Неверная парольная фраза ключа")
    except asyncssh.KeyImportError as e:
        if "passphrase" in str(e).lower():
            raise ValueError("Ключ зашифрован: укажите парольную фразу")
        raise ValueError("Не удалось прочитать закрытый ключ (поддерживаются Ed25519, ECDSA, RSA)")


class _PinningClient(asyncssh.SSHClient):
    """Запоминает предложенный сервером ключ; незакреплённый принимает только в режиме TOFU."""

    def __init__(self, accept_unknown: bool):
        self.accept_unknown = accept_unknown
        self.offered: asyncssh.SSHKey | None = None

    def validate_host_public_key(self, host: str, addr: tuple, port: int, key: asyncssh.SSHKey) -> bool:
        # Вызывается только для ключа, которого нет среди доверенных (закреплённого).
        self.offered = key
        return self.accept_unknown


def _offered(client: _PinningClient) -> HostKeyInfo | None:
    return HostKeyInfo.from_key(client.offered) if client.offered is not None else None


async def connect(
    host: str, port: int, login: Login, pinned: str | None, *, timeout: float = CONNECT_TIMEOUT
) -> tuple[asyncssh.SSHClientConnection, HostKeyInfo]:
    """Подключение с проверкой ключа хоста. pinned — закреплённый открытый ключ («тип base64») или None.

    Возвращает соединение и ключ, который сервер предъявил (для TOFU его закрепляет вызывающий)."""
    trusted = [asyncssh.import_public_key(pinned)] if pinned else []
    client = _PinningClient(accept_unknown=not pinned)
    opts: dict = {
        "port": port,
        "username": login.username,
        "known_hosts": (trusted, [], []),
        "client_factory": lambda: client,
        "config": None,
        "agent_path": None,
        "agent_forwarding": False,
        "x509_trusted_certs": None,
        "gss_auth": False,
        "gss_kex": False,
        "connect_timeout": timeout,
        "login_timeout": timeout,
        "keepalive_interval": 15,
    }
    if login.auth == "key":
        opts |= {
            "client_keys": [import_private_key(login.private_key or "", login.passphrase)],
            "password": None,
            "preferred_auth": "publickey",
        }
    else:
        opts |= {
            "client_keys": None,
            "password": login.password or "",
            "preferred_auth": "keyboard-interactive,password",
        }
    if route is not None:
        addr, opts["port"] = route(host, port)
    else:
        addr = host
    try:
        conn = await asyncssh.connect(addr, **opts)
    except asyncssh.HostKeyNotVerifiable:
        raise SshFailure(
            HOST_KEY_MISMATCH,
            "Ключ хоста не совпадает с закреплённым: возможна подмена (MITM) или переустановка хоста. "
            "Вход не выполнялся",
            _offered(client),
        )
    except asyncssh.KeyExchangeFailed as e:
        if pinned and "host key" in str(e).lower():
            raise SshFailure(
                HOST_KEY_MISMATCH,
                "Сервер не предлагает закреплённый тип ключа хоста. Вход не выполнялся",
                _offered(client),
            )
        raise SshFailure(ERROR, f"Не удалось согласовать алгоритмы SSH: {e}")
    except asyncssh.PermissionDenied:
        raise SshFailure(AUTH_FAILED, "Учётные данные отклонены")
    except TimeoutError:
        raise SshFailure(TIMEOUT, f"{host}:{port} не ответил за {timeout:.0f} с")
    except asyncssh.DisconnectError as e:
        if "timeout" in str(e).lower():
            raise SshFailure(TIMEOUT, f"Вход не уложился в {timeout:.0f} с")
        raise SshFailure(ERROR, f"Сервер разорвал соединение: {e.reason or e}")
    except ConnectionRefusedError:
        raise SshFailure(UNREACHABLE, f"{host}:{port}: соединение отклонено — sshd не слушает этот порт?")
    except OSError as e:
        raise SshFailure(UNREACHABLE, f"{host}:{port}: {e.strerror or e}")
    except asyncssh.Error as e:
        raise SshFailure(ERROR, f"{type(e).__name__}: {e}")
    key = conn.get_server_host_key()
    if key is None:  # GSS-обмен ключами отключён, но на всякий случай
        conn.close()
        raise SshFailure(ERROR, "Сервер не предъявил ключ хоста")
    return conn, HostKeyInfo.from_key(key)


async def run(
    conn: asyncssh.SSHClientConnection, argv: list[str], *, stdin: str | None = None, timeout: float = COMMAND_TIMEOUT
) -> CommandResult:
    """Команда списком аргументов: каждый экранируется, подстановки shell нет."""
    started = time.monotonic()
    try:
        proc = await conn.run(shlex.join(argv), input=stdin, check=False, timeout=timeout)
    except asyncssh.TimeoutError as e:
        raise SshFailure(TIMEOUT, f"Команда {argv[0]} не уложилась в {timeout:.0f} с") from e
    except (asyncssh.Error, OSError) as e:
        raise SshFailure(ERROR, f"{type(e).__name__}: {e}") from e

    def _cut(v: object) -> tuple[str, bool]:
        s = v if isinstance(v, str) else (v or b"").decode("utf-8", "replace") if isinstance(v, bytes) else ""
        return (s[:MAX_OUTPUT], len(s) > MAX_OUTPUT)

    out, t1 = _cut(proc.stdout)
    err, t2 = _cut(proc.stderr)
    return CommandResult(
        returncode=proc.exit_status if proc.exit_status is not None else -1,
        stdout=out,
        stderr=err[-4000:],
        duration_ms=int((time.monotonic() - started) * 1000),
        truncated=t1 or t2,
    )


def _os_name(os_release: str) -> str:
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')[:200]
    return ""


async def check(
    host: str, port: int, login: Login, pinned: str | None, *, timeout: float = CONNECT_TIMEOUT
) -> CheckOutcome:
    """Проверка учётки: вход, кто мы (`id`), ОС и — если нужно — что sudo работает.

    Ничего не меняет на хосте: `id`, чтение `/etc/os-release`, `sudo -k … true`."""
    try:
        conn, key = await connect(host, port, login, pinned, timeout=timeout)
    except SshFailure as e:
        return CheckOutcome(e.code, e.message, e.offered)
    facts: dict = {}
    try:
        async with conn:
            who = await run(conn, ["id", "-un"])
            uid = await run(conn, ["id", "-u"])
            facts["user"] = who.stdout.strip()[:128]
            try:
                facts["uid"] = int(uid.stdout.strip())
            except ValueError:
                return CheckOutcome(ERROR, "Команда id не выполнилась — на хосте не POSIX-оболочка?", key, facts)
            osr = await run(conn, ["cat", "/etc/os-release"])
            facts["os"] = _os_name(osr.stdout) if osr.returncode == 0 else ""
            if facts["uid"] == 0:
                facts["become"] = "root"
            elif login.become == "none":
                facts["become"] = "none"
            else:
                pw = login.sudo_password
                if pw:
                    # -k — не использовать кэш sudo; -p '' — без приглашения; пароль — в stdin.
                    r = await run(conn, ["sudo", "-S", "-k", "-p", "", "true"], stdin=pw + "\n")
                else:
                    r = await run(conn, ["sudo", "-n", "true"])
                if r.returncode != 0:
                    facts["become"] = "failed"
                    hint = "" if pw else " Для входа по ключу без пароля sudo нужен NOPASSWD."
                    return CheckOutcome(BECOME_FAILED, f"Вход выполнен, но sudo отказал.{hint}", key, facts)
                facts["become"] = "sudo"
    except SshFailure as e:
        return CheckOutcome(e.code, e.message, key, facts)
    return CheckOutcome(OK, RESULT_LABELS[OK], key, facts)


def run_sync(coro):  # noqa: ANN001, ANN201
    """Запуск корутины из синхронного кода (обработчики API работают в пуле потоков)."""
    return asyncio.run(coro)
