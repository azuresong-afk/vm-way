"""Сверка копии схем со «Сканером» (tests/scanner_contract_check.py): сама проверка."""

from tests import scanner_contract_check as chk

SCANNER = """
from typing import Literal
from pydantic import BaseModel, Field

Level = Literal["low", "high"]

class Base(BaseModel):
    id: int
    tags: list[str] = Field(default_factory=list)

class RunOut(Base):
    status: str
    level: Level
    node_id: int | None = None

    def helper(self): ...

class Unused(BaseModel):
    x: int
"""

COPY = """
from typing import Literal

Level = Literal["low", "high"]

class _Strict: ...

class RunOut(_Strict):
    id: int
    tags: list[str]
    status: str
    level: Level
    node_id: int | None
"""


def test_equal_copy_passes_ignoring_defaults_inheritance_and_unused_schemas():
    assert chk.compare(COPY, SCANNER) == []


def test_differences_are_reported():
    added = SCANNER.replace("    def helper", "    node_name: str | None = None\n\n    def helper")
    assert chk.compare(COPY, added) == ["RunOut.node_name: поле есть в «Сканере» (str | None), но нет в копии"]
    assert chk.compare(COPY, SCANNER.replace("    status: str\n", "")) == [
        "RunOut.status: поле есть в копии, но его нет в «Сканере»"
    ]
    assert chk.compare(COPY, SCANNER.replace("id: int\n", "id: str\n")) == [
        "RunOut.id: тип в копии int, в «Сканере» str"
    ]
    assert chk.compare(COPY, SCANNER.replace('"high"]', '"high", "critical"]')) == [
        "Level: в копии Literal['low', 'high'], в «Сканере» Literal['low', 'high', 'critical']"
    ]
    assert chk.compare(COPY, SCANNER.replace("class RunOut", "class RunOutV2")) == [
        "RunOut: в «Сканере» такой схемы больше нет"
    ]
    assert chk.compare("X = 1\n", SCANNER) == ["в копии не найдено ни одной схемы"]


def test_cli_exit_codes(tmp_path, capsys):
    """Настоящая копия: совпадает сама с собой, расхождение даёт код 1, плохой запуск — 2."""
    same = tmp_path / "schemas.py"
    same.write_text(chk.CONTRACT.read_text(encoding="utf-8"), encoding="utf-8")
    assert chk.main([str(same)]) == 0
    same.write_text(same.read_text(encoding="utf-8").replace("node_mode: str | None", "node_kind: str"), "utf-8")
    assert chk.main([str(same)]) == 1
    out = capsys.readouterr().out
    assert "RunOut.node_kind: поле есть в «Сканере» (str), но нет в копии" in out
    assert "RunCreated.node_mode: поле есть в копии, но его нет в «Сканере»" in out
    assert chk.main([str(tmp_path / "missing.py")]) == 2
    assert chk.main([]) == 2
