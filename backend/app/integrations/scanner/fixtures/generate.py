"""Генератор демо-фикстуры «Сканера»: 3 ОС, 20 хостов, три плановых прогона.

Данные синтетические, а формы ответов сверены с кодом «Сканера» (репозиторий scanner-way):
FindingOut, FixPlanOut/FixTaskOut (scanner/reporting/fixplan.py), CoverageOut, RunOut,
AllowlistOut, EngagementOut, MeOut. Ключи действий считаются как fixplan._key, dedup_key —
как Finding.dedup_key, приоритет — по шкале R6 (scanner/reporting/risk.py), тексты evidence —
в формате строк auth_inventory, по которым «Сканер» группирует находки в действия.

Запуск: python -m app.integrations.scanner.fixtures.generate > app/integrations/scanner/fixtures/demo.json
"""

import hashlib
import json
import sys

ENGAGEMENT = {
    "id": 7,
    "name": "АО «Северный порт» — аудит защищённости 2026",
    "client": "АО «Северный порт»",
    "contract_ref": "Договор № 14/26-ИБ от 12.08.2026",
    "created_by": 1,
    "created_at": "2026-08-20T09:00:00Z",
}
ALLOWLIST = ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]
CREDENTIAL_IDS = [3]

# family, release (как HostOs), подпись ОС как в «Сканере» (family_label + release), менеджер, источник бюллетеня
OS = {
    "debian": {
        "family": "debian",
        "release": "12",
        "label": "Debian 12",
        "manager": "dpkg",
        "src": "Debian",
        "os_guess": "Debian GNU/Linux 12 (bookworm)",
    },
    "astra": {
        "family": "astra",
        "release": "1.7",
        "label": "Astra Linux 1.7",
        "manager": "dpkg",
        "src": "Astra Linux",
        "os_guess": "Astra Linux SE 1.7",
    },
    "redos": {
        "family": "redos",
        "release": "7.3",
        "label": "РЕД ОС 7.3",
        "manager": "rpm",
        "src": "РЕД ОС",
        "os_guess": "РЕД ОС 7.3",
    },
}

HOSTS = (
    [
        (f"10.20.1.{11 + i}", n, "debian")
        for i, n in enumerate(["web-01", "web-02", "web-03", "web-04", "app-01", "app-02", "db-01", "mon-01"])
    ]
    + [
        (f"10.20.2.{21 + i}", n, "astra")
        for i, n in enumerate(["arm-01", "arm-02", "arm-03", "arm-04", "fs-01", "dc-01"])
    ]
    + [
        (f"10.20.3.{31 + i}", n, "redos")
        for i, n in enumerate(["srv-01", "srv-02", "srv-03", "srv-04", "srv-05", "srv-06"])
    ]
)
BY_NAME = {name: addr for addr, name, _ in HOSTS}
DEB = [n for _, n, o in HOSTS if o == "debian"]
AST = [n for _, n, o in HOSTS if o == "astra"]
RED = [n for _, n, o in HOSTS if o == "redos"]

# Активы и группы активов «Сканера» (AssetOut, AssetGroupOut): владелец, критичность, теги, группы.
# Группа «Резерв» пустая; srv-06 — без группы и владельца (правила по группе его не берут).
ASSET_GROUPS = ["DMZ", "Серверы приложений", "Базы данных", "АРМ сотрудников", "Инфраструктура", "Резерв"]
_G = {name: i + 1 for i, name in enumerate(ASSET_GROUPS)}
OS_FAMILY_LABEL = {"debian": "Debian", "astra": "Astra Linux", "redos": "РЕД ОС"}
ASSET_META = {
    **{n: (["DMZ"], "Отдел веб-сервисов", "high", ["prod", "internet"]) for n in DEB[:4]},
    "app-01": (["Серверы приложений"], "Отдел веб-сервисов", "high", ["prod"]),
    "app-02": (["Серверы приложений"], "Отдел веб-сервисов", "high", ["prod"]),
    "db-01": (["Базы данных"], "Группа СУБД", "critical", ["prod", "pdn"]),
    "mon-01": (["Инфраструктура"], "Отдел эксплуатации", "medium", []),
    **{n: (["АРМ сотрудников"], "Служба поддержки", "low", ["arm"]) for n in AST[:4]},
    "fs-01": (["Инфраструктура"], "Отдел эксплуатации", "critical", ["prod"]),
    "dc-01": (["Инфраструктура"], "Отдел эксплуатации", "critical", ["prod"]),
    "srv-01": (["Серверы приложений", "Базы данных"], "Группа СУБД", "high", ["prod", "pdn"]),
    **{n: (["Серверы приложений"], "Отдел эксплуатации", "medium", ["prod"]) for n in RED[1:5]},
    "srv-06": ([], None, "low", []),
}

# Действия исправления. hosts — по прогонам (100, 101, 102).
# vulns: (CVE, БДУ, CVSS, заголовок). Уровень — по CVSS, как в «Сканере».
ACTIONS = [
    {
        "id": "D1",
        "kind": "package",
        "os": "debian",
        "vendor_pkg": "openssh",
        "pkg": "openssh-server",
        "product": "OpenSSH 9.2p1",
        "installed": "1:9.2p1-2+deb12u2",
        "fixed": "1:9.2p1-2+deb12u3",
        "port": None,
        "adv": "DSA-5724-1",
        "vulns": [("CVE-2024-6387", "BDU:2024-04835", 8.1, "OpenSSH: состояние гонки в обработчике сигналов sshd")],
        "hosts": {100: DEB, 101: DEB, 102: DEB},
    },
    {
        "id": "D2",
        "kind": "package",
        "os": "debian",
        "vendor_pkg": "openssl",
        "pkg": "libssl3",
        "product": "OpenSSL 3.0.13",
        "installed": "3.0.13-1~deb12u1",
        "fixed": "3.0.14-1~deb12u2",
        "port": None,
        "adv": "DSA-5764-1",
        "vulns": [
            ("CVE-2024-5535", "BDU:2024-05121", 9.1, "OpenSSL: чтение за границей буфера в SSL_select_next_proto"),
            ("CVE-2024-4741", "BDU:2024-05350", 7.5, "OpenSSL: использование после освобождения в SSL_free_buffers"),
        ],
        "hosts": {100: DEB[:6], 101: DEB[:6], 102: DEB[:6]},
    },
    {
        "id": "D3",
        "kind": "kernel",
        "os": "debian",
        "running": "6.1.0-21-amd64",
        "fixed": "6.1.106-3",
        "adv": "DSA-5782-1",
        "port": None,
        "vulns": [("CVE-2024-1086", "BDU:2024-00896", 7.8, "Ядро Linux: использование после освобождения в nf_tables")],
        "hosts": {100: DEB, 101: DEB, 102: DEB},
    },
    {
        "id": "D4",
        "kind": "package",
        "os": "debian",
        "vendor_pkg": "sudo",
        "pkg": "sudo",
        "product": "sudo 1.9.13p3",
        "installed": "1.9.13p3-1",
        "fixed": "1.9.13p3-1+deb12u1",
        "port": None,
        "adv": "DSA-5552-1",
        "vulns": [("CVE-2023-28486", "BDU:2023-02121", 5.3, "sudo: неэкранированные управляющие символы в журнале")],
        "hosts": {100: DEB, 101: DEB, 102: []},
    },
    {
        "id": "D5",
        "kind": "package",
        "os": "debian",
        "vendor_pkg": "expat",
        "pkg": "libexpat1",
        "product": "Expat 2.5.0",
        "installed": "2.5.0-1",
        "fixed": "2.5.0-1+deb12u1",
        "port": None,
        "adv": "DSA-5770-1",
        "vulns": [("CVE-2024-45491", "BDU:2024-06931", 9.8, "Expat: переполнение целого в dtdCopy")],
        "hosts": {100: ["db-01", "mon-01"], 101: [], 102: ["mon-01"]},
    },
    {
        "id": "A1",
        "kind": "package",
        "os": "astra",
        "vendor_pkg": "openssh",
        "pkg": "openssh-server",
        "product": "OpenSSH 7.9p1",
        "installed": "1:7.9p1-10+deb10u2+ci202306",
        "fixed": "1:7.9p1-10+deb10u2+ci202407",
        "port": None,
        "adv": "2024-0715SE17",
        "vulns": [("CVE-2023-38408", "BDU:2023-04342", 9.8, "OpenSSH: выполнение кода через PKCS#11 в ssh-agent")],
        "hosts": {100: AST, 101: AST, 102: AST},
    },
    {
        "id": "A2",
        "kind": "package",
        "os": "astra",
        "vendor_pkg": "bind9",
        "pkg": "bind9",
        "product": "BIND 9.11.5",
        "installed": "1:9.11.5.P4+dfsg-5.1+deb10u9",
        "fixed": "1:9.11.5.P4+dfsg-5.1+deb10u11+ci1",
        "port": None,
        "adv": "2024-0829SE17",
        "vulns": [("CVE-2024-1737", "BDU:2024-05612", 7.5, "BIND: отказ в обслуживании при большом числе записей")],
        "hosts": {100: ["fs-01", "dc-01"], 101: ["fs-01", "dc-01"], 102: ["fs-01", "dc-01"]},
    },
    {
        "id": "A3",
        "kind": "package_nofix",
        "os": "astra",
        "vendor_pkg": "tiff",
        "pkg": "libtiff5",
        "product": "LibTIFF 4.1.0",
        "installed": "4.1.0+git191117-2~deb10u8",
        "port": None,
        "adv": None,
        "vulns": [("CVE-2023-52356", "BDU:2024-01811", 6.5, "LibTIFF: отказ в обслуживании в TIFFReadRGBATileExt")],
        "hosts": {100: AST[:4], 101: AST[:4], 102: AST[:4]},
    },
    {
        "id": "A4",
        "kind": "package",
        "os": "astra",
        "vendor_pkg": "libxml2",
        "pkg": "libxml2",
        "product": "libxml2 2.9.4",
        "installed": "2.9.4+dfsg1-7+deb10u6",
        "fixed": "2.9.4+dfsg1-7+deb10u6+ci1",
        "port": None,
        "adv": "2024-1015SE17",
        "vulns": [
            (
                "CVE-2024-25062",
                "BDU:2024-01350",
                7.5,
                "libxml2: использование после освобождения в xmlValidatePopElement",
            )
        ],
        "hosts": {100: [], 101: [], 102: AST[:2]},
    },
    {
        "id": "R1",
        "kind": "package",
        "os": "redos",
        "vendor_pkg": "openssh",
        "pkg": "openssh",
        "product": "OpenSSH 8.8p1",
        "installed": "8.8p1-9.el7",
        "fixed": "8.8p1-12.el7",
        "port": None,
        "adv": "RED-2024-0112",
        "vulns": [("CVE-2023-48795", "BDU:2023-08955", 5.9, "SSH: атака Terrapin на усечение префикса")],
        "hosts": {100: RED, 101: RED, 102: RED},
    },
    {
        "id": "R2",
        "kind": "package",
        "os": "redos",
        "vendor_pkg": "glibc",
        "pkg": "glibc",
        "product": "glibc 2.35",
        "installed": "2.35-6.el7",
        "fixed": "2.35-9.el7",
        "port": None,
        "adv": "RED-2024-0420",
        "vulns": [("CVE-2024-2961", "BDU:2024-03128", 8.8, "glibc: переполнение буфера в iconv (ISO-2022-CN-EXT)")],
        "hosts": {100: RED[:4], 101: RED[:4], 102: RED[1:4]},
    },
    {
        "id": "R3",
        "kind": "kernel",
        "os": "redos",
        "running": "6.1.20-1.el7.x86_64",
        "fixed": "6.1.52-1.el7",
        "adv": "RED-2024-0205",
        "port": None,
        "vulns": [("CVE-2024-1086", "BDU:2024-00896", 7.8, "Ядро Linux: использование после освобождения в nf_tables")],
        "hosts": {100: RED, 101: RED, 102: RED},
    },
    {
        "id": "S1",
        "kind": "software",
        "os": None,
        "software": "Apache Tomcat",
        "installed": "9.0.85",
        "port": 8080,
        "module": "vuln",
        "vulns": [("CVE-2024-52316", "BDU:2024-09876", 9.8, "Apache Tomcat: обход аутентификации Jakarta")],
        "hosts": {100: ["app-01", "app-02"], 101: ["app-01", "app-02"], 102: ["app-01", "app-02"]},
    },
    {
        "id": "C1",
        "kind": "config",
        "os": None,
        "port": 443,
        "module": "vuln",
        "vuln_id": "tls-deprecated-protocols",
        "vulns": [(None, None, 5.3, "Разрешены устаревшие протоколы TLS 1.0 и TLS 1.1")],
        "hosts": {100: DEB[:4], 101: DEB[:4], 102: DEB[:4]},
    },
]

RUNS = [
    {
        "id": 100,
        "name": "Плановый прогон — сентябрь",
        "status": "done",
        "started_at": "2026-09-08T19:00:00Z",
        "finished_at": "2026-09-08T21:40:00Z",
        "unreachable": [],
    },
    {
        "id": 101,
        "name": "Плановый прогон — октябрь",
        "status": "done",
        "started_at": "2026-10-06T19:00:00Z",
        "finished_at": "2026-10-06T21:35:00Z",
        "unreachable": [],
    },
    {
        "id": 102,
        "name": "Плановый прогон — ноябрь",
        "status": "partial",
        "started_at": "2026-11-02T19:00:00Z",
        "finished_at": "2026-11-02T21:52:00Z",
        "unreachable": ["srv-06"],
    },
]
MODULES = ["discovery", "vuln", "auth_inventory"]
COVERAGE_LABELS = {
    "completed": "выполнено",
    "not_applicable": "неприменимо",
    "skipped": "пропущено",
    "unreachable": "хост недоступен",
    "no_credentials": "нет учётной записи",
    "timeout": "таймаут",
    "error": "ошибка",
}

# «Состояние мира» для прицельных прогонов мока: что администраторы уже исправили, но не перепроверили.
# package — имя пакета вендора (как в строке бюллетеня), чтобы исправление закрывало все CVE пакета.
WORLD = {
    "base_run_id": 102,
    "patched": [{"host": BY_NAME[n], "package": "openssh"} for n in ["web-01", "web-02", "web-03", "web-04", "app-01"]]
    + [{"host": BY_NAME[n], "package": "openssh"} for n in RED[:5]]
    + [{"host": BY_NAME[n], "package": "openssl"} for n in DEB[:6]],
    "unreachable": [BY_NAME["mon-01"], BY_NAME["srv-06"]],
    "no_credentials": [BY_NAME["dc-01"]],
}


def dedup_key(host: str, port: int | None, vuln_id: str | None, module: str) -> str:
    """Как Finding.dedup_key в «Сканере»: sha256(host|port|vuln_id|module), None → 'None'."""
    return hashlib.sha256(f"{host}|{port}|{vuln_id}|{module}".encode()).hexdigest()


def fix_key(*parts: object) -> str:
    """Как fixplan._key в «Сканере»."""
    raw = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]  # noqa: S324 — повторяем алгоритм «Сканера»


def severity_of(cvss: float) -> str:
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


def priority_of(cvss: float) -> dict:
    score = round(cvss * 10, 1)
    for threshold, label, label_ru in (
        (85.0, "critical", "Критический приоритет"),
        (65.0, "high", "Высокий приоритет"),
        (40.0, "medium", "Средний приоритет"),
        (0.0, "low", "Низкий приоритет"),
    ):
        if score >= threshold:
            return {
                "rank": None,
                "score": score,
                "label": label,
                "label_ru": label_ru,
                "reasons": [f"CVSS {cvss}"],
                "factors": {
                    "cvss": cvss,
                    "in_kev": False,
                    "epss": None,
                    "epss_percentile": None,
                    "exploit_available": False,
                    "asset_criticality": "medium",
                },
            }
    raise AssertionError


def os_key(a: dict) -> tuple | None:
    if not a["os"]:
        return None
    o = OS[a["os"]]
    return (o["family"], o["release"])


def group_key(a: dict) -> tuple:
    if a["kind"] == "kernel":
        return ("kernel", os_key(a))
    if a["kind"] in ("package", "package_nofix"):
        return (a["kind"], os_key(a), a["vendor_pkg"])
    if a["kind"] == "software":
        return ("software", a["software"].lower())
    return (a["kind"], a.get("vuln_id"))


def evidence(a: dict, cve: str | None) -> str:
    o = OS[a["os"]] if a["os"] else None
    adv = f" ({a['adv']})" if a.get("adv") else ""
    if a["kind"] == "package":
        return (
            f"Пакет {a['pkg']} ({a['installed']}) → {a['product']}\n"
            f"Бюллетень {o['src']}{adv}: {cve} исправлена в версии {a['fixed']} (пакет {a['vendor_pkg']}); "
            f"установлена {a['installed']} — пакет уязвим, обновите его из репозитория дистрибутива."
        )
    if a["kind"] == "package_nofix":
        return (
            f"Пакет {a['pkg']} ({a['installed']}) → {a['product']}\n"
            f"Бюллетень {o['src']}: исправления {cve} для пакета {a['vendor_pkg']} у вендора пока нет — "
            "пакет уязвим."
        )
    if a["kind"] == "kernel":
        return (
            f"Работающее ядро → Ядро Linux {a['running']}\n"
            f"Бюллетень {o['src']}{adv}: {cve} исправлена в ядре версии {a['fixed']}; ядро уязвимо."
        )
    if a["kind"] == "software":
        return f"Баннер сервиса: {a['software']}/{a['installed']}"
    return "Сервер принимает соединения TLSv1.0 и TLSv1.1"


def build_fix(a: dict, items: list[tuple[str, dict]]) -> dict:
    """Действие в форме FixTaskOut (fixplan.FixTask.to_dict)."""
    o = OS[a["os"]] if a["os"] else None
    best = max((f for _, f in items), key=lambda f: f["priority"]["score"])
    sev_rank = ["critical", "high", "medium", "low", "info"]
    fix = {
        "key": fix_key(*group_key(a)),
        "kind": a["kind"],
        "kind_label": {
            "package": "Обновление пакета",
            "package_nofix": "Исправления пока нет",
            "kernel": "Ядро Linux",
            "software": "Обновление ПО",
            "config": "Настройка",
        }[a["kind"]],
        "title": "",
        "os": o["label"] if o else None,
        "os_family": o["family"] if o else None,
        "manager": o["manager"] if o else None,
        "packages": [],
        "fixed_version": None,
        "software": None,
        "steps": [],
        "commands": [],
        "verify": [],
        "reboot": False,
        "details": None,
        "details_source": None,
        "severity": min((f["severity"] for _, f in items), key=sev_rank.index),
        "priority": {k: best["priority"][k] for k in ("score", "label", "label_ru", "rank")},
        "cves": sorted({c for _, f in items for c in f["cve_ids"]}),
        "bdu_ids": sorted({b for _, f in items for b in f["bdu_ids"]}),
        "advisories": [a["adv"]] if a.get("adv") and a["kind"] != "package_nofix" else [],
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{c}" for c in sorted({c for _, f in items for c in f["cve_ids"]})
        ][:8],
        "hosts": [],
        "host_count": 0,
        "finding_count": 0,
    }
    by_host: dict[str, list[dict]] = {}
    for h, f in items:
        by_host.setdefault(h, []).append(f)
    rescan = "Запустите повторный прогон по этим хостам — исправленные находки закроются."
    if a["kind"] == "package":
        fix["packages"] = [a["pkg"]]
        fix["fixed_version"] = a["fixed"]
        fix["title"] = f"Обновить {a['pkg']} до {a['fixed']}"
        fix["steps"] = [
            f"Обновите пакет {a['pkg']} до версии не ниже {a['fixed']} из репозитория {o['src']} "
            f"(бюллетень {a['adv']})."
        ]
        if a["pkg"].startswith(("lib", "openssl", "glibc")):
            tool = "needrestart" if o["manager"] == "dpkg" else "dnf needs-restarting -s"
            fix["steps"].append(
                "Перезапустите службы, которые используют обновлённую библиотеку "
                f"(список покажет `{tool}`), или перезагрузите хост в окно обслуживания."
            )
        fix["steps"].append(rescan)
        if o["manager"] == "dpkg":
            fix["commands"] = ["sudo apt-get update", f"sudo apt-get install --only-upgrade -y {a['pkg']}"]
            fix["verify"] = [f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {a['pkg']}"]
        else:
            fix["commands"] = [f"sudo yum update -y {a['pkg']}"]  # РЕД ОС 7.x — yum
            fix["verify"] = [f"rpm -q {a['pkg']}"]
    elif a["kind"] == "package_nofix":
        fix["packages"] = [a["pkg"]]
        fix["title"] = f"Нет исправления: {a['vendor_pkg']} ({o['label']})"
        fix["steps"] = [
            f"В бюллетенях {o['src']} исправления для пакета {a['vendor_pkg']} пока нет.",
            "До выхода обновления ограничьте доступ к уязвимому компоненту (межсетевой экран, отключение "
            "неиспользуемой функции или службы) и примените меры из описания ниже.",
            "Отслеживайте бюллетень вендора: когда исправление выйдет, это действие сменится на обновление "
            "пакета в следующем прогоне.",
        ]
        fix["details"] = "Ограничьте обработку TIFF-файлов из недоверенных источников."
        fix["details_source"] = "БДУ ФСТЭК"
    elif a["kind"] == "kernel":
        fix["reboot"] = True
        fix["software"] = "Ядро Linux"
        fix["fixed_version"] = a["fixed"]
        fix["title"] = f"Обновить ядро Linux и перезагрузить ({o['label']})"
        fix["steps"] = [
            f"Обновите ядро из репозитория {o['label']} до версии не ниже {a['fixed']}.",
            "Перезагрузите хост в согласованное окно обслуживания — уязвимости ядра закрываются только "
            "после загрузки нового ядра.",
            "Если перезагрузка сейчас невозможна — примените livepatch вендора (Canonical Livepatch, kpatch), "
            "если он подключён.",
            "После перезагрузки проверьте, что работает новое ядро (`uname -r`).",
        ]
        fix["commands"] = (
            ["sudo apt-get update", "sudo apt-get upgrade --with-new-pkgs -y", "sudo reboot"]
            if o["manager"] == "dpkg"
            else ["sudo yum update -y kernel", "sudo reboot"]
        )
        fix["verify"] = ["uname -r"]
    elif a["kind"] == "software":
        fix["software"] = a["software"]
        fix["title"] = f"Обновить {a['software']}"
        fix["steps"] = [
            f"Обновите {a['software']} до версии производителя, в которой исправлены перечисленные уязвимости "
            "(см. бюллетени в ссылках).",
            "Если ПО установлено из пакетов ОС — обновите пакет через менеджер пакетов дистрибутива: тогда "
            "исправленную версию подскажет инвентаризация по учётной записи.",
            "Если обновление сейчас невозможно — ограничьте сетевой доступ к сервису.",
            rescan,
        ]
    else:
        fix["title"] = f"Настроить: {items[0][1]['title']}"
        fix["steps"] = [
            "Оставьте в конфигурации веб-сервера только TLS 1.2 и TLS 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;).",
            rescan,
        ]
    for h in sorted(by_host, key=lambda x: tuple(int(p) for p in x.split("."))):
        fs = by_host[h]
        note = "обновить ядро и перезагрузить" if a["kind"] == "kernel" else None
        installed = a.get("running") if a["kind"] == "kernel" else a.get("installed")
        fix["hosts"].append(
            {
                "host": h,
                "installed": installed,
                "note": note,
                "ports": sorted({f["port"] for f in fs if f["port"]}),
                "findings": [
                    {
                        "id": f["id"],
                        "label": f["cve_ids"][0] if f["cve_ids"] else f["vuln_id"],
                        "severity": f["severity"],
                    }
                    for f in fs
                ],
            }
        )
    fix["host_count"] = len(fix["hosts"])
    fix["finding_count"] = sum(len(h["findings"]) for h in fix["hosts"])
    return fix


def present(a: dict, run_id: int) -> set[str]:
    run = next(r for r in RUNS if r["id"] == run_id)
    return {BY_NAME[n] for n in a["hosts"][run_id] if n not in run["unreachable"]}


def finding_status(a: dict, host_name: str, run_id: int) -> str:
    order = [r["id"] for r in RUNS]
    prev = [r for r in order if r < run_id]
    if not prev:
        return "new"
    if host_name in a["hosts"][prev[-1]]:
        return "open"
    if any(host_name in a["hosts"][r] for r in prev):
        return "regression"
    return "new"


def build_run(run: dict) -> dict:
    run_id = run["id"]
    fid = run_id * 10
    findings: list[dict] = []
    fixes: list[dict] = []
    unreachable = set(run["unreachable"])
    for a in ACTIONS:
        hosts = [h for h in a["hosts"][run_id] if h not in unreachable]
        if not hosts:
            continue
        module = a.get("module", "auth_inventory")
        items: list[tuple[str, dict]] = []
        for hname in hosts:
            addr = BY_NAME[hname]
            for cve, bdu, cvss, title in a["vulns"]:
                fid += 1
                vuln_id = a.get("vuln_id") or cve
                sev = severity_of(cvss)
                if a["kind"] == "software":
                    sw, swv, sws = a["software"], a["installed"], "service"
                elif a["kind"] == "kernel":
                    sw, swv, sws = "Ядро Linux", a["running"], "package"
                elif a["kind"] == "config":
                    sw, swv, sws = None, None, None
                else:
                    sw, swv, sws = a["product"].rsplit(" ", 1)[0], a["installed"], "package"
                f = {
                    "id": fid,
                    "dedup_key": dedup_key(addr, a["port"], vuln_id, module),
                    "module": module,
                    "host": addr,
                    "port": a["port"],
                    "finding_type": "config" if a["kind"] == "config" else "vuln",
                    "title": title,
                    "severity": sev,
                    "vuln_id": vuln_id,
                    "cve_ids": [cve] if cve else [],
                    "bdu_ids": [bdu] if bdu else [],
                    "cvss": cvss,
                    "evidence": evidence(a, cve),
                    "status": finding_status(a, hname, run_id),
                    "detected_at": run["finished_at"],
                    "false_positive": None,
                    "software": sw,
                    "software_version": swv,
                    "software_source": sws,
                    "priority": priority_of(cvss),
                    "confidence": "high" if module == "auth_inventory" else "medium",
                    "source": {"auth_inventory": "vendor_advisory"}.get(
                        module, "config" if a["kind"] == "config" else "nuclei"
                    ),
                }
                findings.append(f)
                items.append((addr, f))
        fixes.append(build_fix(a, items))
    # Ранги приоритета в прогоне (R6: от большего балла к меньшему).
    for rank, f in enumerate(sorted(findings, key=lambda x: (-x["priority"]["score"], x["id"])), start=1):
        f["priority"]["rank"] = rank
    for fx in fixes:
        best = max(
            (f for f in findings if f["id"] in {r["id"] for h in fx["hosts"] for r in h["findings"]}),
            key=lambda f: (f["priority"]["score"], -f["priority"]["rank"]),
        )
        fx["priority"] = {k: best["priority"][k] for k in ("score", "label", "label_ru", "rank")}
    sev_rank = ["critical", "high", "medium", "low", "info"]
    fixes.sort(key=lambda t: (-t["priority"]["score"], sev_rank.index(t["severity"]), -t["host_count"], t["title"]))

    entries = []
    for addr, name, _ in HOSTS:
        for m in MODULES:
            st = "unreachable" if name in unreachable else "completed"
            entries.append(
                {
                    "host": addr,
                    "module": m,
                    "status": st,
                    "label": COVERAGE_LABELS[st],
                    "reason": "хост не ответил на пробы обнаружения" if st == "unreachable" else None,
                }
            )
    warnings = (
        [{"code": "hosts_unreachable", "message": "1 хост недоступен — проверка не выполнена"}] if unreachable else []
    )
    meta = {
        "id": run_id,
        "engagement_id": ENGAGEMENT["id"],
        "modules": MODULES,
        "rate_profile": "normal",
        "credential_ids": CREDENTIAL_IDS,
        "cred_set_ids": [],
        "name": run["name"],
        "targets": ALLOWLIST,
        "schedule_id": 1,
        "status": run["status"],
        "started_by": None,
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "created_at": run["started_at"],
        "error_message": None,
        "retry_of": None,
        "options": {"no_ping": False, "profile": None},
        "warnings": warnings,
        "progress": {"stage": "done", "percent": 100, "hosts_done": len(HOSTS), "hosts_total": len(HOSTS)},
    }
    return {"run": meta, "findings": findings, "fixes": fixes, "coverage_entries": entries}


def build_assets() -> tuple[list[dict], list[dict]]:
    eid = ENGAGEMENT["id"]
    created = "2026-08-20T09:10:00Z"
    assets = []
    for i, (addr, name, o) in enumerate(HOSTS):
        groups, owner, crit, tags = ASSET_META[name]
        assets.append(
            {
                "id": 501 + i,
                "engagement_id": eid,
                "address": addr,
                "hostname": name,
                "owner": owner,
                "criticality": crit,
                "notes": None,
                "tags": sorted(tags),
                "groups": [{"id": _G[g], "name": g} for g in sorted(groups)],
                "created_at": created,
                "os_guess": OS[o]["os_guess"],
                "os_family": OS[o]["family"],
                "os_family_label": OS_FAMILY_LABEL[o],
                "last_run_id": RUNS[-1]["id"],
                "finding_counts": {},
                "findings_total": 0,
                "checked_run_id": RUNS[-1]["id"],
                "source": "discovered",
                "first_seen_at": RUNS[0]["started_at"],
                "last_seen_at": RUNS[-1]["started_at"],
            }
        )
    groups = [
        {
            "id": _G[g],
            "engagement_id": eid,
            "name": g,
            "asset_count": sum(1 for a in assets if any(x["name"] == g for x in a["groups"])),
            "created_at": created,
        }
        for g in sorted(ASSET_GROUPS)
    ]
    return assets, groups


def build() -> dict:
    assets, groups = build_assets()
    return {
        "me": {
            "id": 99,
            "username": "svc-vm",
            "display_name": "Сервисная учётная запись «Устранения»",
            "is_active": True,
            "roles": ["auditor", "operator"],
            "permissions": ["view_report", "run_scan", "host_credentials"],
        },
        "engagements": [ENGAGEMENT],
        "allowlist": {
            str(ENGAGEMENT["id"]): [
                {
                    "id": i + 1,
                    "cidr": c,
                    "note": None,
                    "added_by": 1,
                    "added_at": "2026-08-20T09:05:00Z",
                    "range_spec": None,
                }
                for i, c in enumerate(ALLOWLIST)
            ]
        },
        "hosts": [
            {"address": a, "hostname": n, "os_guess": OS[o]["os_guess"], "os_family": OS[o]["family"]}
            for a, n, o in HOSTS
        ],
        "assets": {str(ENGAGEMENT["id"]): assets},
        "asset_groups": {str(ENGAGEMENT["id"]): groups},
        "runs": [build_run(r) for r in RUNS],
        "world": WORLD,
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
