"""Генератор демо-фикстуры «Сканера»: 3 ОС, 20 хостов, три плановых прогона.

Данные синтетические, но формы ответов повторяют API «Сканера» (findings, fixes, coverage).
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
    "created_by": "admin",
    "created_at": "2026-08-20T09:00:00Z",
}
ALLOWLIST = ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]

OS = {
    "debian": {"os": "Debian GNU/Linux 12 (bookworm)", "short": "Debian 12", "family": "debian", "manager": "apt"},
    "astra": {"os": "Astra Linux SE 1.7", "short": "Astra Linux 1.7", "family": "astra", "manager": "apt"},
    "redos": {"os": "РЕД ОС 7.3", "short": "РЕД ОС 7.3", "family": "redos", "manager": "dnf"},
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

PRIORITY = {
    "critical": {"rank": 1, "score": 92, "label": "P1", "label_ru": "Немедленно"},
    "high": {"rank": 2, "score": 74, "label": "P2", "label_ru": "Срочно"},
    "medium": {"rank": 3, "score": 48, "label": "P3", "label_ru": "Планово"},
    "low": {"rank": 4, "score": 20, "label": "P4", "label_ru": "Низкий"},
}

# Действия исправления: id → описание. hosts — по прогонам (100, 101, 102).
ACTIONS = [
    {
        "id": "D1",
        "kind": "package",
        "os": "debian",
        "package": "openssh-server",
        "installed": "1:9.2p1-2+deb12u2",
        "fixed": "1:9.2p1-2+deb12u3",
        "port": 22,
        "vulns": [
            (
                "CVE-2024-6387",
                "BDU:2024-04835",
                8.1,
                "critical",
                "OpenSSH: состояние гонки в обработчике сигналов sshd (regreSSHion)",
            )
        ],
        "advisories": ["DSA-5724-1"],
        "hosts": {100: DEB, 101: DEB, 102: DEB},
    },
    {
        "id": "D2",
        "kind": "package",
        "os": "debian",
        "package": "libssl3",
        "installed": "3.0.13-1~deb12u1",
        "fixed": "3.0.14-1~deb12u2",
        "port": None,
        "vulns": [
            (
                "CVE-2024-5535",
                "BDU:2024-05121",
                9.1,
                "high",
                "OpenSSL: чтение за границей буфера в SSL_select_next_proto",
            ),
            (
                "CVE-2024-4741",
                "BDU:2024-05350",
                7.5,
                "high",
                "OpenSSL: использование после освобождения в SSL_free_buffers",
            ),
        ],
        "advisories": ["DSA-5764-1"],
        "hosts": {100: DEB[:6], 101: DEB[:6], 102: DEB[:6]},
    },
    {
        "id": "D3",
        "kind": "kernel",
        "os": "debian",
        "package": "linux-image-amd64",
        "installed": "6.1.90-1",
        "fixed": "6.1.106-3",
        "port": None,
        "reboot": True,
        "vulns": [
            ("CVE-2024-1086", "BDU:2024-00896", 7.8, "high", "Ядро Linux: использование после освобождения в nf_tables")
        ],
        "advisories": ["DSA-5782-1"],
        "hosts": {100: DEB, 101: DEB, 102: DEB},
    },
    {
        "id": "D4",
        "kind": "package",
        "os": "debian",
        "package": "sudo",
        "installed": "1.9.13p3-1",
        "fixed": "1.9.13p3-1+deb12u1",
        "port": None,
        "vulns": [
            ("CVE-2023-28486", "BDU:2023-02121", 5.3, "medium", "sudo: неэкранированные управляющие символы в журнале")
        ],
        "advisories": ["DSA-5552-1"],
        "hosts": {100: DEB, 101: DEB, 102: []},
    },
    {
        "id": "D5",
        "kind": "package",
        "os": "debian",
        "package": "libexpat1",
        "installed": "2.5.0-1",
        "fixed": "2.5.0-1+deb12u1",
        "port": None,
        "vulns": [("CVE-2024-45491", "BDU:2024-06931", 9.8, "medium", "Expat: переполнение целого в dtdCopy")],
        "advisories": ["DSA-5770-1"],
        "hosts": {100: ["db-01", "mon-01"], 101: [], 102: ["mon-01"]},
    },
    {
        "id": "A1",
        "kind": "package",
        "os": "astra",
        "package": "openssh-server",
        "installed": "1:7.9p1-10+deb10u2+ci202306",
        "fixed": "1:7.9p1-10+deb10u2+ci202407",
        "port": 22,
        "vulns": [
            ("CVE-2023-38408", "BDU:2023-04342", 9.8, "high", "OpenSSH: выполнение кода через PKCS#11 в ssh-agent")
        ],
        "advisories": ["2024-0715SE17"],
        "hosts": {100: AST, 101: AST, 102: AST},
    },
    {
        "id": "A2",
        "kind": "package",
        "os": "astra",
        "package": "bind9",
        "installed": "1:9.11.5.P4+dfsg-5.1+deb10u9",
        "fixed": "1:9.11.5.P4+dfsg-5.1+deb10u11+ci1",
        "port": 53,
        "vulns": [
            ("CVE-2024-1737", "BDU:2024-05612", 7.5, "high", "BIND: отказ в обслуживании при большом числе записей")
        ],
        "advisories": ["2024-0829SE17"],
        "hosts": {100: ["fs-01", "dc-01"], 101: ["fs-01", "dc-01"], 102: ["fs-01", "dc-01"]},
    },
    {
        "id": "A3",
        "kind": "package_nofix",
        "os": "astra",
        "package": "libtiff5",
        "installed": "4.1.0+git191117-2~deb10u8",
        "fixed": "",
        "port": None,
        "vulns": [
            ("CVE-2023-52356", "BDU:2024-01811", 7.5, "medium", "LibTIFF: отказ в обслуживании в TIFFReadRGBATileExt")
        ],
        "advisories": [],
        "hosts": {100: AST[:4], 101: AST[:4], 102: AST[:4]},
    },
    {
        "id": "A4",
        "kind": "package",
        "os": "astra",
        "package": "libxml2",
        "installed": "2.9.4+dfsg1-7+deb10u6",
        "fixed": "2.9.4+dfsg1-7+deb10u6+ci1",
        "port": None,
        "vulns": [
            (
                "CVE-2024-25062",
                "BDU:2024-01350",
                7.5,
                "medium",
                "libxml2: использование после освобождения в xmlValidatePopElement",
            )
        ],
        "advisories": ["2024-1015SE17"],
        "hosts": {100: [], 101: [], 102: AST[:2]},
    },
    {
        "id": "R1",
        "kind": "package",
        "os": "redos",
        "package": "openssh",
        "installed": "8.8p1-9.el7",
        "fixed": "8.8p1-12.el7",
        "port": 22,
        "vulns": [("CVE-2023-48795", "BDU:2023-08955", 5.9, "medium", "SSH: атака Terrapin на усечение префикса")],
        "advisories": ["RED-2024-0112"],
        "hosts": {100: RED, 101: RED, 102: RED},
    },
    {
        "id": "R2",
        "kind": "package",
        "os": "redos",
        "package": "glibc",
        "installed": "2.35-6.el7",
        "fixed": "2.35-9.el7",
        "port": None,
        "vulns": [
            ("CVE-2024-2961", "BDU:2024-03128", 8.8, "high", "glibc: переполнение буфера в iconv (ISO-2022-CN-EXT)")
        ],
        "advisories": ["RED-2024-0420"],
        "hosts": {100: RED[:4], 101: RED[:4], 102: RED[1:4]},
    },
    {
        "id": "R3",
        "kind": "kernel",
        "os": "redos",
        "package": "kernel-lt",
        "installed": "6.1.20-1.el7",
        "fixed": "6.1.52-1.el7",
        "port": None,
        "reboot": True,
        "vulns": [
            ("CVE-2024-1086", "BDU:2024-00896", 7.8, "high", "Ядро Linux: использование после освобождения в nf_tables")
        ],
        "advisories": ["RED-2024-0205"],
        "hosts": {100: RED, 101: RED, 102: RED},
    },
    {
        "id": "S1",
        "kind": "software",
        "os": "",
        "package": "Apache Tomcat",
        "module": "vuln",
        "installed": "9.0.85",
        "fixed": "9.0.96",
        "port": 8080,
        "vulns": [("CVE-2024-52316", "BDU:2024-09876", 9.8, "critical", "Apache Tomcat: обход аутентификации Jakarta")],
        "advisories": [],
        "hosts": {100: ["app-01", "app-02"], 101: ["app-01", "app-02"], 102: ["app-01", "app-02"]},
    },
    {
        "id": "C1",
        "kind": "config",
        "os": "",
        "package": "nginx",
        "module": "vuln",
        "installed": "",
        "fixed": "",
        "port": 443,
        "vuln_id": "tls-deprecated-protocols",
        "vulns": [(None, None, 5.3, "medium", "Разрешены устаревшие протоколы TLS 1.0 и TLS 1.1")],
        "advisories": [],
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
        "warnings": ["Хост 10.20.3.36 недоступен: проверка не выполнена"],
    },
]
MODULES = ["discovery", "vuln", "auth_inventory"]

# «Состояние мира» для прицельных прогонов мока: что администраторы уже исправили, но не перепроверили.
WORLD = {
    "base_run_id": 102,
    "patched": [
        {"host": BY_NAME[n], "package": "openssh-server", "os_family": "debian"}
        for n in ["web-01", "web-02", "web-03", "web-04", "app-01"]
    ]
    + [{"host": BY_NAME[n], "package": "openssh", "os_family": "redos"} for n in RED[:5]]
    + [{"host": BY_NAME[n], "package": "libssl3", "os_family": "debian"} for n in DEB[:6]],
    "unreachable": [BY_NAME["mon-01"], BY_NAME["srv-06"]],
    "no_credentials": [BY_NAME["dc-01"]],
}


def sha(*parts: object) -> str:
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()


def action_title(a: dict) -> str:
    osd = OS[a["os"]]["short"] if a["os"] else ""
    if a["kind"] == "package":
        return f"Обновить {a['package']} на {osd} до {a['fixed']}"
    if a["kind"] == "kernel":
        return f"Обновить ядро ({a['package']}) на {osd} до {a['fixed']}"
    if a["kind"] == "package_nofix":
        return f"{a['package']} на {osd}: исправления у производителя нет"
    if a["kind"] == "software":
        return f"Обновить {a['package']} до {a['fixed']}"
    return "Отключить TLS 1.0 и TLS 1.1 в nginx"


def commands(a: dict) -> tuple[list[str], list[str], list[str]]:
    pkg = a["package"]
    mgr = OS[a["os"]]["manager"] if a["os"] else ""
    if a["kind"] in ("package", "kernel"):
        if mgr == "apt":
            cmds = ["apt-get update", f"apt-get install --only-upgrade {pkg}"]
            verify = [f"dpkg-query -W -f='${{Version}}\\n' {pkg}"]
        else:
            cmds = [f"dnf upgrade -y {pkg}"]
            verify = [f"rpm -q {pkg}"]
        steps = [f"Обновить пакет {pkg} до версии {a['fixed']} или новее."]
        if a.get("reboot"):
            steps.append("Перезагрузить хост, чтобы загрузилось новое ядро.")
            verify.append("uname -r")
        elif a.get("port") == 22:
            steps.append("Перезапустить службу sshd.")
            cmds.append("systemctl restart ssh" if mgr == "apt" else "systemctl restart sshd")
        return steps, cmds, verify
    if a["kind"] == "package_nofix":
        return (
            [
                "Исправленной версии пока нет. Ограничьте обработку недоверенных TIFF-файлов.",
                "Следите за бюллетенями производителя.",
            ],
            [],
            [f"dpkg-query -W {pkg}"],
        )
    if a["kind"] == "software":
        return (
            [
                f"Обновить Apache Tomcat до версии {a['fixed']} или новее.",
                "Перезапустить службу Tomcat и проверить работу приложений.",
            ],
            [],
            ["curl -sI http://localhost:8080/"],
        )
    return (
        [
            "В конфигурации nginx оставить только TLS 1.2 и TLS 1.3: ssl_protocols TLSv1.2 TLSv1.3;",
            "Проверить конфигурацию и перезагрузить nginx.",
        ],
        ["nginx -t", "systemctl reload nginx"],
        ["openssl s_client -connect localhost:443 -tls1_1 </dev/null"],
    )


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
        osinfo = OS[a["os"]] if a["os"] else None
        title = action_title(a)
        key = sha(a["kind"], osinfo["os"] if osinfo else "", a["package"])[:24]
        fix_hosts = []
        cves = [v[0] for v in a["vulns"] if v[0]]
        bdus = [v[1] for v in a["vulns"] if v[1]]
        sev = a["vulns"][0][3]
        for hname in hosts:
            addr = BY_NAME[hname]
            refs = []
            for cve, bdu, cvss, vsev, vtitle in a["vulns"]:
                fid += 1
                vuln_id = a.get("vuln_id") or cve
                f = {
                    "id": fid,
                    "dedup_key": sha(addr, a["port"], vuln_id, module),
                    "module": module,
                    "host": addr,
                    "port": a["port"],
                    "finding_type": "config" if a["kind"] == "config" else "vuln",
                    "title": vtitle,
                    "severity": vsev,
                    "vuln_id": vuln_id,
                    "cve_ids": [cve] if cve else [],
                    "bdu_ids": [bdu] if bdu else [],
                    "cvss": cvss,
                    "evidence": f"{a['package']} {a['installed']}".strip(),
                    "status": "open",
                    "detected_at": run["finished_at"],
                    "software": a["package"],
                    "software_version": a["installed"],
                    "priority": {**PRIORITY[vsev], "reasons": ["Уровень по CVSS"], "factors": {}},
                    "confidence": "high" if module == "auth_inventory" else "medium",
                    "source": module,
                    "false_positive": False,
                }
                findings.append(f)
                refs.append({"id": fid, "label": cve or vtitle, "severity": vsev})
            fix_hosts.append(
                {
                    "host": addr,
                    "installed": a["installed"],
                    "note": "",
                    "ports": [a["port"]] if a["port"] else [],
                    "findings": refs,
                }
            )
        steps, cmds, verify = commands(a)
        fixes.append(
            {
                "key": key,
                "kind": a["kind"],
                "title": title,
                "os": osinfo["os"] if osinfo else "",
                "os_family": osinfo["family"] if osinfo else "",
                "manager": osinfo["manager"] if osinfo and a["kind"] in ("package", "kernel", "package_nofix") else "",
                "packages": [a["package"]] if a["kind"] in ("package", "kernel", "package_nofix") else [],
                "fixed_version": a["fixed"],
                "steps": steps,
                "commands": cmds,
                "verify": verify,
                "reboot": bool(a.get("reboot")),
                "severity": sev,
                "priority": {**PRIORITY[sev], "reasons": [], "factors": {}},
                "cves": cves,
                "bdu_ids": bdus,
                "advisories": a["advisories"],
                "references": [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves],
                "hosts": fix_hosts,
                "host_count": len(fix_hosts),
                "finding_count": sum(len(h["findings"]) for h in fix_hosts),
            }
        )
    coverage = []
    for addr, name, _ in HOSTS:
        for m in MODULES:
            st = "unreachable" if name in unreachable else "completed"
            coverage.append(
                {
                    "host": addr,
                    "module": m,
                    "status": st,
                    "reason": "Хост не ответил на запросы" if st == "unreachable" else "",
                }
            )
    meta = {
        "id": run_id,
        "engagement_id": ENGAGEMENT["id"],
        "name": run["name"],
        "modules": MODULES,
        "targets": ALLOWLIST,
        "status": run["status"],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "progress": 100,
        "warnings": run.get("warnings", []),
        "options": {"rate_profile": "normal"},
    }
    return {"run": meta, "findings": findings, "fixes": fixes, "coverage": coverage}


def build() -> dict:
    return {
        "engagements": [ENGAGEMENT],
        "allowlist": {str(ENGAGEMENT["id"]): ALLOWLIST},
        "hosts": [{"address": a, "hostname": n, "os": OS[o]["os"], "os_family": OS[o]["family"]} for a, n, o in HOSTS],
        "runs": [build_run(r) for r in RUNS],
        "world": WORLD,
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
