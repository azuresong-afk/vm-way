"""Общие помощники API: пагинация, ошибки."""

from fastapi import HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

MAX_LIMIT = 500


def paginate(db: Session, stmt: Select, response: Response, limit: int, offset: int) -> list:
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    response.headers["X-Total-Count"] = str(total)
    return list(db.scalars(stmt.limit(limit).offset(offset)))


def not_found(what: str = "Объект") -> HTTPException:
    return HTTPException(404, f"{what} не найден")
