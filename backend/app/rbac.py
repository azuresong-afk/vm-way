"""Роли, права и проверка доступа на каждый запрос."""

from enum import StrEnum


class Perm(StrEnum):
    VIEW = "view"
    IMPORT = "import"
    TICKET_WORK = "ticket_work"
    TICKET_ASSIGN = "ticket_assign"
    TICKET_OVERRIDE = "ticket_override"
    VERIFY = "verify"
    PROJECTS_MANAGE = "projects_manage"
    SOURCES_MANAGE = "sources_manage"
    USERS_MANAGE = "users_manage"
    AUDIT_VIEW = "audit_view"
    # Права-надбавки (этап 2): выдаются поверх роли.
    REMEDIATE_EXECUTE = "remediate_execute"
    CUSTOM_COMMANDS = "custom_commands"


ROLES: dict[str, dict] = {
    "manager": {
        "label": "Руководитель",
        "perms": {
            Perm.VIEW,
            Perm.IMPORT,
            Perm.TICKET_WORK,
            Perm.TICKET_ASSIGN,
            Perm.TICKET_OVERRIDE,
            Perm.VERIFY,
            Perm.AUDIT_VIEW,
        },
    },
    "engineer": {
        "label": "Исполнитель",
        "perms": {Perm.VIEW, Perm.IMPORT, Perm.TICKET_WORK, Perm.VERIFY},
    },
    "viewer": {"label": "Наблюдатель", "perms": {Perm.VIEW}},
    # Администратор не выполняет рабочих операций (разделение обязанностей).
    "admin": {
        "label": "Администратор",
        "perms": {Perm.VIEW, Perm.PROJECTS_MANAGE, Perm.SOURCES_MANAGE, Perm.USERS_MANAGE, Perm.AUDIT_VIEW},
    },
}

EXTRA_PERMS: dict[str, str] = {
    Perm.REMEDIATE_EXECUTE: "Запуск раскатки на хостах",
    Perm.CUSTOM_COMMANDS: "Произвольные команды вне шаблонов",
}
# Надбавки действуют только поверх роли исполнителя или руководителя.
EXTRA_REQUIRES = {"engineer", "manager"}


def perms_for(roles: list[str], extra: list[str]) -> set[str]:
    out: set[str] = set()
    for role in roles:
        out |= {str(p) for p in ROLES.get(role, {}).get("perms", set())}
    if EXTRA_REQUIRES & set(roles):
        out |= {p for p in extra if p in EXTRA_PERMS}
    return out
