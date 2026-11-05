"""Шаблоны раскатки (задача 2.4): какие команды выполняются на хосте и как читается их вывод.

Данные шаблона (имена пакетов, версия, имя службы) пришли со сканируемых хостов и могут быть
враждебны. Поэтому:

- каждое значение проверяется регулярным выражением до сохранения раскатки и ещё раз перед запуском
  (`^[A-Za-z0-9][A-Za-z0-9+.:~_-]*$` для пакетов и версий — из ТЗ);
- команда — всегда список аргументов; строка для SSH собирается `shlex.join` (каждый аргумент
  в кавычках), подстановок shell нет;
- значение не может начинаться с «-», поэтому не превращается в ключ команды.

Произвольная команда (`custom`) — тоже список аргументов: строка, введённая человеком с правом
`custom_commands`, разбирается `shlex.split` на сервере, и раскатка её только исполняет.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]*$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]*$")
MAX_NAME = 128
MAX_PACKAGES = 30
MAX_COMMAND = 2000

TEMPLATES = {
    "package": "Обновление пакетов",
    "kernel": "Обновление ядра",
    "service": "Перезапуск службы",
    "custom": "Произвольная команда",
}
MANAGERS = {
    "apt": "apt — Debian, Astra Linux, Ubuntu",
    "apt-rpm": "apt-rpm — ALT Linux",
    "dnf": "dnf — РЕД ОС, RHEL 8+",
    "yum": "yum — CentOS 7, РЕД ОС 7.2",
    "zypper": "zypper — SUSE",
    "apk": "apk — Alpine",
}
RPM_MANAGERS = {"apt-rpm", "dnf", "yum", "zypper"}
# Пакет ядра по умолчанию: метапакет, который тянет свежее ядро.
KERNEL_PACKAGES = {
    "apt": ["linux-image-amd64"],
    "apt-rpm": ["kernel-image-std-def"],
    "dnf": ["kernel"],
    "yum": ["kernel"],
    "zypper": ["kernel-default"],
    "apk": ["linux-lts"],
}
_FAMILY = {
    "debian": "apt",
    "ubuntu": "apt",
    "astra": "apt",
    "alt": "apt-rpm",
    "altlinux": "apt-rpm",
    "redos": "dnf",
    "rhel": "dnf",
    "centos": "yum",
    "rocky": "dnf",
    "alma": "dnf",
    "almalinux": "dnf",
    "oracle": "dnf",
    "fedora": "dnf",
    "sles": "zypper",
    "suse": "zypper",
    "opensuse": "zypper",
    "alpine": "apk",
}
_BY_SCANNER = {"dpkg": "apt", "rpm": "dnf", "apk": "apk"}

# Таймауты команд, секунды.
QUERY_TIMEOUT = 60
REFRESH_TIMEOUT = 300
UPGRADE_TIMEOUT = 1800
SERVICE_TIMEOUT = 120
CUSTOM_TIMEOUT = 600


class TemplateError(Exception):
    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.message = message
        self.code = code


def default_manager(os_family: str, scanner_manager: str | None) -> str:
    fam = (os_family or "").lower()
    if fam in _FAMILY:
        return _FAMILY[fam]
    return _BY_SCANNER.get((scanner_manager or "").lower(), "")


def check_name(value: str, what: str = "пакета") -> str:
    v = str(value or "").strip()
    if not v or len(v) > MAX_NAME or not NAME_RE.match(v):
        raise TemplateError(
            f"Недопустимое имя {what}: «{v[:60]}». Допустимы латиница, цифры и «+ . : ~ _ -», "
            "первый символ — буква или цифра"
        )
    return v


def check_version(value: str | None) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if len(v) > MAX_NAME or not NAME_RE.match(v):
        raise TemplateError(f"Недопустимая версия: «{v[:60]}»")
    return v


def check_service(value: str) -> str:
    v = str(value or "").strip()
    if not v or len(v) > MAX_NAME or not SERVICE_RE.match(v):
        raise TemplateError(f"Недопустимое имя службы: «{v[:60]}». Допустимы латиница, цифры и «@ . _ : -»")
    return v


def parse_command(text: str) -> list[str]:
    """Произвольная команда: строка → список аргументов (без shell)."""
    text = (text or "").strip()
    if not text:
        raise TemplateError("Укажите команду")
    if len(text) > MAX_COMMAND:
        raise TemplateError(f"Команда длиннее {MAX_COMMAND} символов")
    if "\n" in text or "\x00" in text:
        raise TemplateError("Команда — одна строка")
    try:
        argv = shlex.split(text)
    except ValueError as e:
        raise TemplateError(f"Не удалось разобрать команду: {e}")
    if not argv:
        raise TemplateError("Укажите команду")
    return argv


# ---------- команды ----------


def query_cmd(manager: str, packages: list[str]) -> list[str]:
    """Установленные версии пакетов (только чтение)."""
    if manager == "apt":
        return ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n", *packages]
    if manager == "apk":
        return ["apk", "list", "--installed", *packages]
    return ["rpm", "-q", "--qf", "%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\n", *packages]


def refresh_cmd(manager: str) -> list[str] | None:
    """Обновить списки пакетов. dnf и yum обновляют метаданные сами."""
    return {
        "apt": ["apt-get", "update", "-q"],
        "apt-rpm": ["apt-get", "update", "-q"],
        "zypper": ["zypper", "--non-interactive", "refresh"],
        "apk": ["apk", "update"],
    }.get(manager)


def simulate_cmd(manager: str, packages: list[str]) -> list[str]:
    """Пробный прогон: штатный «сухой» режим менеджера пакетов."""
    return {
        "apt": ["apt-get", "-s", "install", "--only-upgrade", "-y", *packages],
        "apt-rpm": ["apt-get", "-s", "install", "-y", *packages],
        "dnf": ["dnf", "upgrade", "--assumeno", *packages],
        "yum": ["yum", "update", "--assumeno", *packages],
        "zypper": ["zypper", "--non-interactive", "update", "--dry-run", *packages],
        "apk": ["apk", "upgrade", "--simulate", *packages],
    }[manager]


def upgrade_cmd(manager: str, packages: list[str]) -> list[str]:
    return {
        "apt": [
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "--only-upgrade",
            "-y",
            "-o",
            "Dpkg::Options::=--force-confold",
            *packages,
        ],
        "apt-rpm": ["apt-get", "install", "-y", *packages],
        "dnf": ["dnf", "upgrade", "-y", *packages],
        "yum": ["yum", "update", "-y", *packages],
        "zypper": ["zypper", "--non-interactive", "update", *packages],
        "apk": ["apk", "upgrade", *packages],
    }[manager]


def reboot_check_cmd(manager: str) -> list[str]:
    """Нужна ли перезагрузка после обновления (у apt — файл-флаг, у rpm — needs-restarting)."""
    if manager == "apt":
        return ["test", "-e", "/var/run/reboot-required"]
    return ["needs-restarting", "-r"]


def reboot_needed(manager: str, returncode: int) -> bool | None:
    if manager == "apt":
        return returncode == 0
    if returncode in (0, 1):  # needs-restarting -r: 1 — нужна перезагрузка
        return returncode == 1
    return None  # утилиты нет — неизвестно


BOOT_ID_CMD = ["cat", "/proc/sys/kernel/random/boot_id"]
KERNEL_CMD = ["uname", "-r"]
REBOOT_CMD = ["systemctl", "reboot"]


def service_state_cmd(service: str) -> list[str]:
    return ["systemctl", "show", "--property=LoadState,ActiveState", service]


def service_restart_cmd(service: str) -> list[str]:
    return ["systemctl", "restart", service]


def service_active_cmd(service: str) -> list[str]:
    return ["systemctl", "is-active", service]


def parse_service_state(stdout: str) -> dict[str, str]:
    out = {}
    for line in stdout.splitlines():
        k, _, v = line.partition("=")
        if k in ("LoadState", "ActiveState"):
            out[k] = v.strip()
    return out


# ---------- разбор вывода ----------


def parse_versions(manager: str, stdout: str, packages: list[str]) -> dict[str, str | None]:
    """Версии пакетов из вывода query_cmd; не установлен — None."""
    found: dict[str, str] = {}
    if manager == "apk":
        for line in stdout.splitlines():
            for p in packages:
                m = re.match(rf"^{re.escape(p)}-(\d\S*)\s", line)
                if m:
                    found[p] = m.group(1)
    else:
        for line in stdout.splitlines():
            name, sep, ver = line.partition("\t")
            if not sep or not ver.strip():
                continue
            ver = ver.strip()
            if manager in RPM_MANAGERS and ver.startswith("(none):"):
                ver = ver[len("(none):") :]
            found[name.strip()] = ver
    return {p: found.get(p) for p in packages}


_APT_INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+)")
_APK_UPG = re.compile(r"^\(\d+/\d+\) (?:Upgrading|Updating) (\S+) \((\S+) -> (\S+)\)")
_RPM_ROW = re.compile(
    r"^\s+(\S+)\s+(?:x86_64|noarch|i686|aarch64|ppc64le|s390x|e2k\S*)\s+(\S+)\s+\S+\s+[\d.,]+\s*[kMG]?\s*$"
)
_RPM_SECTIONS = ("Upgrading:", "Updating:", "Installing:", "Installing dependencies:", "Updating dependencies:")


def parse_plan(manager: str, stdout: str) -> list[dict]:
    """Что изменится по выводу пробного прогона: [{package, from, to}]. Не разобралось — пусто."""
    plan: list[dict] = []
    if manager in ("apt", "apt-rpm"):
        for line in stdout.splitlines():
            m = _APT_INST.match(line)
            if m:
                plan.append({"package": m.group(1), "from": m.group(2) or "", "to": m.group(3)})
    elif manager in ("dnf", "yum"):
        section = False
        for line in stdout.splitlines():
            if line.strip() in _RPM_SECTIONS:
                section = True
                continue
            if section and not line.startswith(" "):
                section = False
            m = _RPM_ROW.match(line) if section else None
            if m:
                plan.append({"package": m.group(1), "from": "", "to": m.group(2)})
    elif manager == "apk":
        for line in stdout.splitlines():
            m = _APK_UPG.match(line)
            if m:
                plan.append({"package": m.group(1), "from": m.group(2), "to": m.group(3)})
    elif manager == "zypper":
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            if re.match(r"^The following \d+ packages? (?:is|are) going to be upgraded:", line):
                for name in (lines[i + 1] if i + 1 < len(lines) else "").split():
                    plan.append({"package": name, "from": "", "to": ""})
    return plan


def simulate_ok(manager: str, returncode: int, stdout: str) -> bool:
    if returncode == 0:
        return True
    # dnf/yum --assumeno завершаются кодом 1 с «Operation aborted» — это и есть «сухой» режим.
    return manager in ("dnf", "yum") and returncode == 1 and "Operation aborted" in stdout


def rollback_hint(manager: str, package: str, version: str) -> str:
    """Подсказка для отката к версии «до» (команда только показывается, не выполняется)."""
    bare = version.split(":", 1)[1] if manager in RPM_MANAGERS and ":" in version else version
    return {
        "apt": f"apt-get install {package}={version}",
        "apt-rpm": f"apt-get install {package}={version}",
        "dnf": f"dnf downgrade {package}-{bare}",
        "yum": f"yum downgrade {package}-{bare}",
        "zypper": f"zypper install --oldpackage {package}-{bare}",
        "apk": f"apk add {package}={version}",
    }.get(manager, "")


# ---------- сравнение версий ----------


def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a: str, b: str) -> int:
    """Сравнение части версии по правилам dpkg: нецифровой префикс, затем число, и так далее."""
    while a or b:
        na, nb = re.match(r"\D*", a).group(), re.match(r"\D*", b).group()
        for k in range(max(len(na), len(nb))):
            ac = _deb_order(na[k]) if k < len(na) else 0
            bc = _deb_order(nb[k]) if k < len(nb) else 0
            if ac != bc:
                return -1 if ac < bc else 1
        a, b = a[len(na) :], b[len(nb) :]
        da, db = re.match(r"\d*", a).group(), re.match(r"\d*", b).group()
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
        a, b = a[len(da) :], b[len(db) :]
    return 0


def _split_evr(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    if not epoch.isdigit():
        epoch, rest = "0", v
    upstream, _, release = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), upstream, release


def deb_compare(a: str, b: str) -> int:
    """Сравнение версий Debian (как `dpkg --compare-versions`)."""
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part(ua, ub) or _deb_part(ra, rb)


def _rpm_segment(a: str, b: str) -> int:
    """rpmvercmp: сравнение по сегментам цифр и букв, «~» — раньше всего."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] != "~":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] != "~":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            sa = re.match(r"\d+", a[i:]).group()
            sb_m = re.match(r"\d+", b[j:])
            if not sb_m:
                return 1
            sb = sb_m.group()
            na, nb = int(sa), int(sb)
            if na != nb:
                return -1 if na < nb else 1
        else:
            sa = re.match(r"[A-Za-z]+", a[i:]).group()
            sb_m = re.match(r"[A-Za-z]+", b[j:])
            if not sb_m:
                return -1
            sb = sb_m.group()
            if sa != sb:
                return -1 if sa < sb else 1
        i += len(sa)
        j += len(sb)
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpm_segment(va, vb) or (_rpm_segment(ra, rb) if ra and rb else 0)


def compare(manager: str, a: str, b: str) -> int:
    return deb_compare(a, b) if manager == "apt" else rpm_compare(a, b)


@dataclass(frozen=True)
class Plan:
    """Проверенные параметры шаблона — то, что реально уйдёт на хост."""

    template: str
    manager: str
    packages: tuple[str, ...]
    fixed_version: str
    service: str
    command: tuple[str, ...]


def build_plan(
    template: str, manager: str, packages: list[str], fixed_version: str, service: str, command: list[str]
) -> Plan:
    """Проверка параметров шаблона (при подготовке и ещё раз перед каждым запуском)."""
    if template not in TEMPLATES:
        raise TemplateError("Неизвестный шаблон раскатки")
    if template in ("package", "kernel"):
        if manager not in MANAGERS:
            raise TemplateError("Выберите менеджер пакетов")
        pkgs: list[str] = []
        for p in packages or []:
            p = check_name(p)
            if p not in pkgs:
                pkgs.append(p)
        if not pkgs:
            raise TemplateError("Укажите хотя бы один пакет")
        if len(pkgs) > MAX_PACKAGES:
            raise TemplateError(f"Не больше {MAX_PACKAGES} пакетов в одной раскатке")
        return Plan(template, manager, tuple(pkgs), check_version(fixed_version), "", ())
    if template == "service":
        return Plan(template, "", (), "", check_service(service), ())
    argv = [str(a) for a in command or []]
    if not argv or not argv[0]:
        raise TemplateError("Укажите команду")
    if sum(len(a) for a in argv) > MAX_COMMAND or any("\x00" in a or "\n" in a for a in argv):
        raise TemplateError("Недопустимая команда")
    return Plan(template, "", (), "", "", tuple(argv))
