"""Подключение к БД и сессии."""

from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite возвращает «наивные» даты — считаем их UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def make_engine(url: str) -> Engine:
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _rec):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


engine = make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def configure(url: str) -> None:
    """Переключение БД (тесты)."""
    global engine
    engine = make_engine(url)
    SessionLocal.configure(bind=engine)


def lock_project(db: Session, project_id: str) -> None:
    """Блокировка проекта до конца транзакции: импорт прогонов и синхронизация активов одного
    проекта идут строго по очереди, даже из разных потоков и процессов.

    Без неё два параллельных импорта оба не видят ещё не зафиксированные строки друг друга
    (группы активов, уязвимости, заявки) и создают их дважды: один падает на уникальном ключе,
    а история появления и исчезновения уязвимостей может сложиться не в порядке прогонов.

    Это рекомендательная блокировка PostgreSQL (advisory lock): она никого не задерживает, кроме
    других вызовов lock_project для того же проекта, и снимается сама при commit или rollback.
    На SQLite ничего не делает — там и так один пишущий.
    """
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": f"vm.project:{project_id}"})


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
