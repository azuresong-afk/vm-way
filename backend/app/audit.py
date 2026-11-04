"""Журнал аудита (append-only) и outbox доменных событий."""

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import AuditLog, Outbox, User

# Ключи, которые никогда не попадают в журнал (секреты).
_SECRET_KEYS = {"password", "secret", "token", "private_key", "passphrase", "api_token"}


def _clean(details: dict | None) -> dict | None:
    if details is None:
        return None
    return {k: ("***" if k.lower() in _SECRET_KEYS else v) for k, v in details.items()}


def record(
    db: Session,
    user: User | None,
    action: str,
    *,
    object_type: str = "",
    object_id: str | int | None = "",
    project_id: str | None = None,
    result: str = "ok",
    ip: str = "",
    details: dict | None = None,
) -> AuditLog:
    """Добавляет запись в текущую транзакцию: она фиксируется вместе с изменением."""
    entry = AuditLog(
        user_id=user.id if user else None,
        user_sub=(user.platform_sub or str(user.id)) if user else "",
        username=user.username if user else "система",
        action=action,
        object_type=object_type,
        object_id=str(object_id or ""),
        project_id=project_id,
        result=result,
        ip=ip,
        details=_clean(details),
    )
    db.add(entry)
    # Каждая запись аудита дублируется событием для сводного журнала платформы.
    emit(
        db,
        "audit.recorded",
        project_id,
        f"audit/{action}",
        {
            "action": action,
            "object_type": object_type,
            "object_id": str(object_id or ""),
            "result": result,
            "user": entry.username,
        },
    )
    return entry


def record_separately(user: User | None, action: str, **kwargs) -> None:
    """Запись в отдельной транзакции (отказы доступа, ошибки) — не зависит от отката основной."""
    db = SessionLocal()
    try:
        record(db, user, action, **kwargs)
        db.commit()
    finally:
        db.close()


def emit(db: Session, type_: str, project_id: str | None, subject: str, data: dict) -> Outbox:
    """Доменное событие в той же транзакции (доставка в платформу — этап 3)."""
    ev = Outbox(type=type_, project_id=project_id, subject=subject, data=data)
    db.add(ev)
    return ev
