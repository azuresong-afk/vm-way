"""Манифест продукта (контракт платформы, п. 5) и проверки готовности."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import schema
from app.config import get_settings
from app.db import get_db
from app.rbac import ROLES

router = APIRouter(tags=["meta"])

NAV = [
    {"id": "summary", "label": "Сводка", "path": "/vm/", "icon": "layout-dashboard", "perm": "view"},
    {"id": "tickets", "label": "Заявки", "path": "/vm/tickets", "icon": "list-checks", "perm": "view"},
    {"id": "my", "label": "Мои задачи", "path": "/vm/my", "icon": "user-check", "perm": "ticket_work"},
]


@router.get("/manifest")
def manifest() -> dict:
    return {
        "id": "vm",
        "title": "Устранение",
        "subtitle": "управление уязвимостями",
        "icon": "wrench",
        "base_path": "/vm/",
        "api_base": "/api/vm/",
        "version": get_settings().product_version,
        "roles": {k: v["label"] for k, v in ROLES.items() if k != "admin"},
        "nav": NAV,
        "search_url": "/api/vm/search",
        "health_url": "/api/vm/health/ready",
    }


@router.get("/health/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    """Готов к работе: БД доступна и схема на последней миграции."""
    try:
        db.execute(text("SELECT 1"))
        current = schema.current_revision(db)
    except Exception:
        raise HTTPException(503, "БД недоступна")
    head = schema.head_revision()
    if current != head:
        raise HTTPException(503, f"Схема БД не на последней миграции: {current or 'нет'}, нужна {head}")
    return {"status": "ok"}
