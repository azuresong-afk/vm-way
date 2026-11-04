"""Начальная настройка: первый администратор и демо-данные."""

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.models import AssignmentRule, MaintenanceWindow, Project, ScannerSource, SourceLink, Team, User
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
    # Правила назначения (задача 2.2): DMZ и серверы приложений — команде по загрузке, РЕД ОС — исполнителю.
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
                groups=["DMZ", "Серверы приложений"],
                team_id=team.id,
            )
        )
        db.add(
            AssignmentRule(
                project_id=pr.id,
                position=2,
                name="Ядро РЕД ОС — Ковалёву",
                os=["РЕД ОС 7.3"],
                kinds=["kernel"],
                assignee_id=staff["engineer2"].id,
            )
        )
        db.flush()
    audit.record(db, None, "demo.seed", object_type="project", object_id=pr.id, project_id=pr.id)
    db.commit()
    return pr
