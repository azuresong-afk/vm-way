"""SSH-учётки проекта и закрепление ключей хостов (задача 2.3).

Учётка — логин и пароль или закрытый ключ, порт и повышение прав (`sudo` | `none`). Секреты
шифруются AES-GCM (`app.security.encrypt_secret`) с контекстом `ssh-credential:<id>`, наружу не
отдаются, в журнал не пишутся.

Охват учётки — адреса и подсети и группы активов «Сканера»; пустой — все хосты проекта.
Выбор: для хоста берётся самая точная подходящая учётка — адрес в списке, затем группа, затем
подсеть (чем уже, тем точнее), затем учётка без охвата; при равенстве — созданная раньше.
Отключённые учётки не выбираются.

Ключи хостов закрепляются по проекту, адресу и порту: один и тот же 10.0.0.5 у разных заказчиков —
разные машины. Первое подключение закрепляет ключ (TOFU). Другой ключ — отказ до входа, хост
помечается «ключ изменился», и подключаться к нему нельзя, пока руководитель не примет новый ключ
или не сбросит закрепление (оба действия — с причиной, в журнал).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import utcnow
from app.models import Asset, HostKey, SshCredential, Ticket, TicketHost, User, Vulnerability
from app.security import decrypt_secret, encrypt_secret
from app.services import sshexec
from app.services.assets import assets_by_address

AUTH_KINDS = {"password": "Пароль", "key": "Ключ SSH"}
BECOME_KINDS = {"sudo": "sudo", "none": "Без повышения"}
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,254}$")
MAX_SECRET = 16 * 1024
MAX_SCOPE = 500
SECRET_FIELDS = ("password", "private_key", "passphrase", "become_password")


class CredentialError(Exception):
    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.message = message
        self.code = code


# ---------- секреты ----------


def _context(c: SshCredential) -> str:
    return f"ssh-credential:{c.id}"


def read_secrets(c: SshCredential) -> dict[str, str]:
    if not c.secret_enc:
        return {}
    return json.loads(decrypt_secret(c.secret_enc, _context(c)))


def write_secrets(c: SshCredential, secrets: dict[str, str | None]) -> None:
    """Шифрует секреты учётки. Нужен id — вызывать после flush."""
    data = {k: v for k, v in secrets.items() if k in SECRET_FIELDS and v}
    c.secret_enc = encrypt_secret(json.dumps(data), _context(c))
    c.has_become_password = bool(data.get("become_password"))


def login_for(c: SshCredential) -> sshexec.Login:
    s = read_secrets(c)
    return sshexec.Login(
        username=c.username,
        auth=c.auth,
        become=c.become,
        password=s.get("password"),
        private_key=s.get("private_key"),
        passphrase=s.get("passphrase"),
        become_password=s.get("become_password"),
    )


# ---------- проверка полей ----------


def clean_scope(hosts: list[str] | None) -> list[str]:
    """Адреса, подсети (нормализуются в CIDR) и имена хостов без повторов."""
    out: list[str] = []
    for raw in hosts or []:
        h = str(raw).strip()
        if not h:
            continue
        if "/" in h:
            try:
                h = str(ipaddress.ip_network(h, strict=False))
            except ValueError:
                raise CredentialError(f"Недопустимая подсеть: {h[:80]}")
        elif not HOST_RE.match(h):
            raise CredentialError(f"Недопустимый адрес: {h[:80]}")
        if h not in out:
            out.append(h)
    if len(out) > MAX_SCOPE:
        raise CredentialError(f"В охвате не больше {MAX_SCOPE} адресов и подсетей")
    return out


def clean_groups(groups: list[str] | None) -> list[str]:
    out: list[str] = []
    for g in groups or []:
        g = str(g).strip()[:128]
        if g and g not in out:
            out.append(g)
    return out


def validate(c: SshCredential, secrets: dict[str, str | None]) -> None:
    """Проверка полей учётки и итоговых секретов (после изменения)."""
    c.name = (c.name or "").strip()
    if not c.name:
        raise CredentialError("Укажите название учётки")
    c.username = (c.username or "").strip()
    if not USER_RE.match(c.username):
        raise CredentialError("Недопустимый логин: латиница, цифры, «_ . @ -», до 128 символов")
    if c.auth not in AUTH_KINDS:
        raise CredentialError("Способ входа — пароль или ключ")
    if c.become not in BECOME_KINDS:
        raise CredentialError("Повышение прав — sudo или без повышения")
    if not 1 <= int(c.port or 0) <= 65535:
        raise CredentialError("Порт — от 1 до 65535")
    for k in SECRET_FIELDS:
        if len(secrets.get(k) or "") > MAX_SECRET:
            raise CredentialError("Секрет длиннее 16 КБ")
    if c.auth == "password":
        if not secrets.get("password"):
            raise CredentialError("Укажите пароль")
        c.key_type = c.key_fingerprint = ""
    else:
        if not secrets.get("private_key"):
            raise CredentialError("Вставьте закрытый ключ")
        try:
            key = sshexec.import_private_key(secrets["private_key"] or "", secrets.get("passphrase"))
        except ValueError as e:
            raise CredentialError(str(e))
        c.key_type = key.get_algorithm()
        c.key_fingerprint = key.get_fingerprint("sha256")
    c.hosts = clean_scope(c.hosts)
    c.groups = clean_groups(c.groups)
    c.note = (c.note or "").strip()[:2000]


def snapshot(c: SshCredential) -> dict:
    """Поля учётки для журнала — без секретов."""
    return {
        "name": c.name,
        "username": c.username,
        "auth": c.auth,
        "port": c.port,
        "become": c.become,
        "key_fingerprint": c.key_fingerprint,
        "has_become_password": c.has_become_password,
        "hosts": c.hosts,
        "groups": c.groups,
        "is_active": c.is_active,
    }


# ---------- выбор учётки для хоста ----------


def project_hosts(db: Session, project_id: str) -> set[str]:
    """Хосты проекта: активы «Сканера», хосты уязвимостей и заявок."""
    out = set(db.scalars(select(Asset.address).where(Asset.project_id == project_id)))
    out |= set(db.scalars(select(Vulnerability.host).where(Vulnerability.project_id == project_id).distinct()))
    out |= set(
        db.scalars(
            select(TicketHost.host)
            .join(Ticket, Ticket.id == TicketHost.ticket_id)
            .where(Ticket.project_id == project_id)
        )
    )
    return out


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass
class Match:
    credential: SshCredential
    why: str  # host | group | subnet | all
    detail: str = ""


def match(c: SshCredential, host: str, host_groups: set[str]) -> tuple[tuple, Match] | None:
    """Подходит ли учётка хосту; ключ сортировки — чем меньше, тем точнее."""
    if host in (c.hosts or []):
        return (0, 0, c.id), Match(c, "host", host)
    groups = [g for g in (c.groups or []) if g in host_groups]
    if groups:
        return (1, 0, c.id), Match(c, "group", groups[0])
    ip = _ip(host)
    best: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    if ip is not None:
        for spec in c.hosts or []:
            if "/" not in spec:
                continue
            net = ipaddress.ip_network(spec, strict=False)
            if net.version == ip.version and ip in net and (best is None or net.prefixlen > best.prefixlen):
                best = net
    if best is not None:
        return (2, -best.prefixlen, c.id), Match(c, "subnet", str(best))
    if not c.hosts and not c.groups:
        return (3, 0, c.id), Match(c, "all")
    return None


def resolve(creds: list[SshCredential], host: str, host_groups: set[str]) -> Match | None:
    found = [m for c in creds if c.is_active and (m := match(c, host, host_groups))]
    return min(found, key=lambda x: x[0])[1] if found else None


def project_credentials(db: Session, project_id: str) -> list[SshCredential]:
    return list(
        db.scalars(select(SshCredential).where(SshCredential.project_id == project_id).order_by(SshCredential.id))
    )


def host_groups(db: Session, project_id: str, host: str) -> set[str]:
    asset = db.scalar(select(Asset).where(Asset.project_id == project_id, Asset.address == host))
    return {g.name for g in asset.groups} if asset else set()


def credential_for_host(db: Session, project_id: str, host: str) -> Match | None:
    """Учётка, которой «Устранение» пойдёт на хост (для раскатки, задача 2.4)."""
    return resolve(project_credentials(db, project_id), host, host_groups(db, project_id, host))


# ---------- ключи хостов ----------


def get_host_key(db: Session, project_id: str, host: str, port: int) -> HostKey | None:
    return db.scalar(
        select(HostKey).where(HostKey.project_id == project_id, HostKey.host == host, HostKey.port == port)
    )


def _record_mismatch(
    db: Session, hk: HostKey, offered: sshexec.HostKeyInfo | None, actor: User | None, ip: str, via: str
) -> None:
    hk.status = "mismatch"
    hk.mismatch_at = utcnow()
    hk.mismatch_count = (hk.mismatch_count or 0) + 1
    if offered is not None:
        hk.mismatch_key_type = offered.key_type
        hk.mismatch_fingerprint = offered.fingerprint
        hk.mismatch_public_key = offered.public_key
    audit.record(
        db,
        actor,
        "host_key.mismatch",
        object_type="host_key",
        object_id=hk.id,
        project_id=hk.project_id,
        result="denied",
        ip=ip,
        details={
            "host": hk.host,
            "port": hk.port,
            "pinned": hk.fingerprint,
            "offered": offered.fingerprint if offered else "",
            "via": via,
        },
    )


def observe_key(
    db: Session, project_id: str, host: str, port: int, key: sshexec.HostKeyInfo, actor: User | None, ip: str, via: str
) -> tuple[HostKey, bool]:
    """Ключ, с которым вход прошёл: закрепить при первом подключении (TOFU) или отметить «виден».

    Возвращает (запись, совпал ли ключ). Если параллельное подключение успело закрепить другой
    ключ — несовпадение (как при отказе до входа)."""
    now = utcnow()
    hk = get_host_key(db, project_id, host, port)
    if hk is None:
        hk = HostKey(
            project_id=project_id,
            host=host,
            port=port,
            key_type=key.key_type,
            fingerprint=key.fingerprint,
            public_key=key.public_key,
            pinned_via="tofu",
            pinned_by=actor.id if actor else None,
            pinned_at=now,
            last_seen_at=now,
        )
        # Вызывается до других изменений в транзакции: при гонке двух первых подключений откат
        # ничего лишнего не теряет.
        db.add(hk)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            hk = get_host_key(db, project_id, host, port)
            if hk is None:
                raise
        else:
            audit.record(
                db,
                actor,
                "host_key.pin",
                object_type="host_key",
                object_id=hk.id,
                project_id=project_id,
                ip=ip,
                details={
                    "host": host,
                    "port": port,
                    "key_type": key.key_type,
                    "fingerprint": key.fingerprint,
                    "via": via,
                },
            )
            return hk, True
    if hk.public_key != key.public_key:
        _record_mismatch(db, hk, key, actor, ip, via)
        return hk, False
    hk.last_seen_at = now
    return hk, True


def accept_new_key(db: Session, hk: HostKey, actor: User, reason: str, ip: str) -> None:
    if hk.status != "mismatch" or not hk.mismatch_public_key:
        raise CredentialError("Новый ключ не записан: принимать нечего", 409)
    old = hk.fingerprint
    hk.key_type, hk.fingerprint, hk.public_key = hk.mismatch_key_type, hk.mismatch_fingerprint, hk.mismatch_public_key
    hk.status, hk.pinned_via, hk.pinned_by, hk.pinned_at = "pinned", "accepted", actor.id, utcnow()
    hk.mismatch_key_type = hk.mismatch_fingerprint = hk.mismatch_public_key = ""
    hk.mismatch_at = None
    audit.record(
        db,
        actor,
        "host_key.accept",
        object_type="host_key",
        object_id=hk.id,
        project_id=hk.project_id,
        ip=ip,
        details={"host": hk.host, "port": hk.port, "from": old, "to": hk.fingerprint, "reason": reason},
    )


def reset_key(db: Session, hk: HostKey, actor: User, reason: str, ip: str) -> None:
    audit.record(
        db,
        actor,
        "host_key.reset",
        object_type="host_key",
        object_id=hk.id,
        project_id=hk.project_id,
        ip=ip,
        details={
            "host": hk.host,
            "port": hk.port,
            "fingerprint": hk.fingerprint,
            "status": hk.status,
            "reason": reason,
        },
    )
    db.delete(hk)


def key_out(hk: HostKey, users: dict[int, str] | None = None) -> dict:
    return {
        "id": hk.id,
        "host": hk.host,
        "port": hk.port,
        "key_type": hk.key_type,
        "fingerprint": hk.fingerprint,
        "status": hk.status,
        "pinned_via": hk.pinned_via,
        "pinned_by": (users or {}).get(hk.pinned_by) if hk.pinned_by else None,
        "pinned_at": hk.pinned_at,
        "last_seen_at": hk.last_seen_at,
        "mismatch": (
            {
                "key_type": hk.mismatch_key_type,
                "fingerprint": hk.mismatch_fingerprint,
                "at": hk.mismatch_at,
                "count": hk.mismatch_count,
            }
            if hk.status == "mismatch"
            else None
        ),
    }


# ---------- проверка входа ----------


def check(db: Session, c: SshCredential, host: str, actor: User | None, ip: str = "") -> dict:
    """Проверить учётку на хосте: вход, sudo, закрепление ключа. Результат пишется в учётку и журнал."""
    hk = get_host_key(db, c.project_id, host, c.port)
    key_state = "pinned" if hk else "new"
    if hk is not None and hk.status == "mismatch":
        outcome = sshexec.CheckOutcome(
            sshexec.HOST_KEY_MISMATCH,
            "Ключ хоста ранее не совпал с закреплённым. Подключения запрещены, пока руководитель "
            "не примет новый ключ или не сбросит закрепление",
        )
        key_state = "mismatch"
    else:
        outcome = sshexec.run_sync(sshexec.check(host, c.port, login_for(c), hk.public_key if hk else None))
        if outcome.code == sshexec.HOST_KEY_MISMATCH:
            if hk is not None:
                _record_mismatch(db, hk, outcome.key, actor, ip, "check")
            key_state = "mismatch"
        elif outcome.key is not None:
            hk, same = observe_key(db, c.project_id, host, c.port, outcome.key, actor, ip, "check")
            if not same:
                outcome = sshexec.CheckOutcome(sshexec.HOST_KEY_MISMATCH, "Ключ хоста не совпал с закреплённым")
                key_state = "mismatch"
    c.last_check_at = utcnow()
    c.last_check_host = host
    c.last_check_result = outcome.code
    c.last_check_message = outcome.message[:1000]
    audit.record(
        db,
        actor,
        "ssh_credential.check",
        object_type="ssh_credential",
        object_id=c.id,
        project_id=c.project_id,
        result="ok" if outcome.ok else "error",
        ip=ip,
        details={"name": c.name, "host": host, "port": c.port, "result": outcome.code, "key": key_state},
    )
    hk = get_host_key(db, c.project_id, host, c.port)
    return {
        "result": outcome.code,
        "label": sshexec.RESULT_LABELS.get(outcome.code, outcome.code),
        "message": outcome.message,
        "ok": outcome.ok,
        "facts": outcome.facts,
        "key_state": key_state,
        "host_key": key_out(hk) if hk else None,
    }


# ---------- вывод ----------


def credential_out(c: SshCredential) -> dict:
    return {
        "id": c.id,
        "project_id": c.project_id,
        "name": c.name,
        "username": c.username,
        "auth": c.auth,
        "port": c.port,
        "become": c.become,
        "key_type": c.key_type,
        "key_fingerprint": c.key_fingerprint,
        "has_secret": bool(c.secret_enc),
        "has_become_password": c.has_become_password,
        "hosts": c.hosts or [],
        "groups": c.groups or [],
        "is_active": c.is_active,
        "note": c.note,
        "last_check": (
            {
                "at": c.last_check_at,
                "host": c.last_check_host,
                "result": c.last_check_result,
                "label": sshexec.RESULT_LABELS.get(c.last_check_result, c.last_check_result),
                "message": c.last_check_message,
            }
            if c.last_check_at
            else None
        ),
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


def _host_sort(h: str) -> tuple:
    ip = _ip(h)
    return (0, ip.version, int(ip)) if ip is not None else (1, 0, h)


def hosts_overview(db: Session, project_id: str) -> list[dict]:
    """Хосты проекта: какой учёткой пойдём и что с ключом хоста."""
    assets = assets_by_address(db, project_id)
    creds = project_credentials(db, project_id)
    keys: dict[str, list[HostKey]] = {}
    for hk in db.scalars(select(HostKey).where(HostKey.project_id == project_id).order_by(HostKey.port)):
        keys.setdefault(hk.host, []).append(hk)
    in_project = project_hosts(db, project_id)
    user_ids = {hk.pinned_by for lst in keys.values() for hk in lst if hk.pinned_by}
    users = {u.id: u.display_name or u.username for u in db.scalars(select(User).where(User.id.in_(user_ids)))}
    out = []
    for host in sorted(in_project | set(keys), key=_host_sort):
        a = assets.get(host)
        groups = {g.name for g in a.groups} if a else set()
        m = resolve(creds, host, groups)
        out.append(
            {
                "host": host,
                "hostname": a.hostname if a else "",
                "groups": sorted(groups),
                "in_project": host in in_project,
                "credential": (
                    {
                        "id": m.credential.id,
                        "name": m.credential.name,
                        "username": m.credential.username,
                        "port": m.credential.port,
                        "why": m.why,
                        "detail": m.detail,
                    }
                    if m
                    else None
                ),
                "keys": [key_out(hk, users) for hk in keys.get(host, [])],
            }
        )
    return out
