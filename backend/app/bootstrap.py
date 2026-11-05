"""Начальная настройка: первый администратор и демо-данные."""

import logging
import secrets
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import utcnow
from app.models import (
    AssignmentRule,
    HostKey,
    MaintenanceWindow,
    Project,
    ScannerSource,
    SourceLink,
    SshCredential,
    Team,
    User,
)
from app.security import hash_password

log = logging.getLogger("vm.bootstrap")

DEMO_USERS = [
    ("manager", "Петрова А. С.", ["manager"], []),
    ("engineer", "Смирнов Д. В.", ["engineer"], ["remediate_execute"]),
    ("engineer2", "Ковалёв И. Н.", ["engineer"], []),
    ("viewer", "Орлова Е. М. (заказчик)", ["viewer"], []),
]


def ensure_admin(db: Session) -> None:
    s = get_settings()
    if db.scalar(select(func.count()).select_from(User)):
        return
    if not s.admin_password:
        log.warning("Пользователей нет, а VM_ADMIN_PASSWORD не задан — администратор не создан")
        return
    admin = User(
        username=s.admin_username,
        display_name="Администратор",
        password_hash=hash_password(s.admin_password),
        roles=["admin"],
    )
    db.add(admin)
    db.flush()
    audit.record(
        db, None, "user.bootstrap_admin", object_type="user", object_id=admin.id, details={"username": admin.username}
    )
    db.commit()
    log.info("Создан первый администратор %s", admin.username)


def ensure_demo(db: Session) -> Project | None:
    """Демо: проект, источник mock://demo с привязкой к проекту «Сканера» №7 и пользователи
    (пароль — VM_DEMO_PASSWORD). Прогоны подтянет опрос источника."""
    s = get_settings()
    if not s.demo:
        return None
    pr = db.scalar(select(Project).where(Project.name == "Демо: АО «Северный порт»"))
    if pr:
        return pr
    pr = Project(
        name="Демо: АО «Северный порт»", client="АО «Северный порт»", contract_ref="Договор № 14/26-ИБ от 12.08.2026"
    )
    db.add(pr)
    db.flush()
    src = ScannerSource(
        name="Демо-«Сканер» (встроенный мок)",
        base_url="mock://demo",
        username="svc-vm",
        auto_import=True,
        poll_minutes=15,
    )
    db.add(src)
    db.flush()
    db.add(
        SourceLink(
            source_id=src.id,
            project_id=pr.id,
            engagement_id=7,
            engagement_name="АО «Северный порт» — аудит защищённости 2026",
        )
    )
    if s.demo_password:
        for username, name, roles, extra in DEMO_USERS:
            if not db.scalar(select(User).where(User.username == username)):
                db.add(
                    User(
                        username=username,
                        display_name=name,
                        roles=roles,
                        extra_perms=extra,
                        password_hash=hash_password(s.demo_password),
                    )
                )
    # Окна обслуживания (задача 2.1): ночное окно по вторникам и четвергам и новогодний блэкаут.
    db.add(
        MaintenanceWindow(
            project_id=pr.id,
            name="Ночное окно",
            kind="recurring",
            weekdays=[1, 3],
            start_time="22:00",
            duration_minutes=240,
            note="Согласовано с заказчиком письмом от 20.10.2026",
        )
    )
    db.add(
        MaintenanceWindow(
            project_id=pr.id,
            name="Новогодняя заморозка",
            kind="blackout",
            starts_at=datetime(2026, 12, 29, 21, tzinfo=UTC),
            ends_at=datetime(2027, 1, 11, 6, tzinfo=UTC),
            note="Изменения в инфраструктуре заказчика запрещены",
        )
    )
    db.flush()
    # Правила назначения (задача 2.2): DMZ и серверы приложений — команде по загрузке, ядро РЕД ОС —
    # исполнителю. Выключены: иначе импорт сразу назначит заявки и проход этапа 1 в TESTING.md
    # («остальные — Новая») не сойдётся; правила включаются в шаге 12.
    staff = {u.username: u for u in db.scalars(select(User).where(User.username.in_(["engineer", "engineer2"])))}
    if len(staff) == 2:
        team = db.scalar(select(Team).where(Team.name == "Веб-сервисы"))
        if team is None:
            team = Team(name="Веб-сервисы", members=[staff["engineer"], staff["engineer2"]])
            db.add(team)
            db.flush()
        db.add(
            AssignmentRule(
                project_id=pr.id,
                position=1,
                name="DMZ и приложения — команде веб-сервисов",
                is_active=False,
                groups=["DMZ", "Серверы приложений"],
                team_id=team.id,
            )
        )
        db.add(
            AssignmentRule(
                project_id=pr.id,
                position=2,
                name="Ядро РЕД ОС — Ковалёву",
                is_active=False,
                os=["РЕД ОС 7.3"],
                kinds=["kernel"],
                assignee_id=staff["engineer2"].id,
            )
        )
        db.flush()
    _demo_ssh(db, pr.id)
    audit.record(db, None, "demo.seed", object_type="project", object_id=pr.id, project_id=pr.id)
    db.commit()
    return pr


def _demo_ssh(db: Session, project_id: str) -> None:
    """SSH-учётки и ключи хостов (задача 2.3): пароль для серверов и ключ для БД; ключи трёх
    хостов закреплены, у web-03 ключ «изменился». Хосты демо — поддельные SSH-серверы демо-стенда
    (app/integrations/sshsim.py, задача 2.4): закреплены их настоящие ключи, у web-03 закреплён
    «старый» ключ, а стенд предъявляет новый."""
    import asyncssh

    from app.integrations import sshsim
    from app.services import credentials

    sim = sshsim.demo()

    now = utcnow()
    servers = SshCredential(
        project_id=project_id,
        name="Linux-серверы (deploy)",
        username="deploy",
        auth="password",
        become="sudo",
        hosts=["10.20.1.0/24", "10.20.3.0/24"],
        note="Учётка выдана заказчиком на период работ, sudo без ограничений",
        last_check_at=now,
        last_check_host="10.20.1.11",
        last_check_result="ok",
        last_check_message="Вход выполнен",
    )
    db_key = asyncssh.generate_private_key("ssh-ed25519", comment="vm-demo")
    databases = SshCredential(
        project_id=project_id,
        name="Базы данных (ключ)",
        username="vm-patch",
        auth="key",
        become="sudo",
        groups=["Базы данных"],
        note="Ключ только для серверов БД, sudo NOPASSWD на apt и dnf",
    )
    db.add_all([servers, databases])
    db.flush()
    credentials.write_secrets(servers, {"password": secrets.token_urlsafe(18)})
    pem = db_key.export_private_key("openssh").decode()
    credentials.write_secrets(databases, {"private_key": pem})
    databases.key_type, databases.key_fingerprint = db_key.get_algorithm(), db_key.get_fingerprint("sha256")

    def _pub() -> tuple[str, str, str]:
        k = asyncssh.generate_private_key("ssh-ed25519")
        return k.get_algorithm(), k.get_fingerprint("sha256"), " ".join(k.export_public_key().decode().split()[:2])

    for host in ("10.20.1.11", "10.20.1.12", "10.20.1.15", "10.20.1.13"):
        kt, fp, pub = sim.public_key(host) if sim and host != "10.20.1.13" else _pub()
        hk = HostKey(
            project_id=project_id,
            host=host,
            port=22,
            key_type=kt,
            fingerprint=fp,
            public_key=pub,
            pinned_at=now,
            last_seen_at=now,
        )
        if host == "10.20.1.13":
            kt2, fp2, pub2 = sim.public_key(host) if sim else _pub()
            hk.status, hk.mismatch_key_type, hk.mismatch_fingerprint, hk.mismatch_public_key = (
                "mismatch",
                kt2,
                fp2,
                pub2,
            )
            hk.mismatch_at, hk.mismatch_count = now, 1
        db.add(hk)
    db.flush()
