"""Версия схемы БД: последняя миграция в коде и применённая в базе."""

from functools import lru_cache
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

ALEMBIC_DIR = Path(__file__).resolve().parents[1] / "alembic"


@lru_cache
def head_revision() -> str:
    cfg = Config()
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"Цепочка миграций разветвлена: {heads}")
    return heads[0]


def current_revision(db: Session) -> str | None:
    """Применённая миграция или None, если миграций в базе нет."""
    if not inspect(db.get_bind()).has_table("alembic_version"):
        return None
    return db.execute(text("SELECT version_num FROM alembic_version")).scalar()
