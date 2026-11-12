"""Сверка копии схем (tests/scanner_contract.py) с оригиналом из scanner-way.

    python -m tests.scanner_contract_check путь/к/scanner-way/scanner/api/schemas.py

Оба файла разбираются как текст (ast), код «Сканера» не импортируется и не исполняется,
зависимости не нужны. Для каждой схемы копии сверяются набор полей и их типы (с учётом
наследования), а также псевдонимы типов вроде `Criticality = Literal[...]`. Значения по
умолчанию не сверяются. Схемы «Сканера», которых в копии нет, не проверяются: «Устранение»
их не читает. Код возврата: 0 — совпадает, 1 — есть расхождения, 2 — ошибка запуска.
"""

import ast
import sys
from pathlib import Path

CONTRACT = Path(__file__).with_name("scanner_contract.py")


def parse(source: str) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Возвращает ({схема: {поле: тип}}, {псевдоним типа: определение})."""
    raw: dict[str, tuple[list[str], dict[str, str]]] = {}
    aliases: dict[str, str] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            own = {
                s.target.id: ast.unparse(s.annotation)
                for s in node.body
                if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
            }
            raw[node.name] = ([ast.unparse(b) for b in node.bases], own)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Subscript | ast.BinOp):
                aliases[node.targets[0].id] = ast.unparse(node.value)

    def fields(name: str) -> dict[str, str]:
        bases, own = raw.get(name, ([], {}))
        out: dict[str, str] = {}
        for base in reversed(bases):
            out.update(fields(base))
        return {**out, **own}

    return {name: fields(name) for name in raw}, aliases


def _names(annotation: str) -> set[str]:
    return {n.id for n in ast.walk(ast.parse(annotation, mode="eval")) if isinstance(n, ast.Name)}


def compare(contract_src: str, scanner_src: str) -> list[str]:
    """Список расхождений копии с оригиналом; пустой — всё совпадает."""
    ours, our_aliases = parse(contract_src)
    theirs, their_aliases = parse(scanner_src)
    problems: list[str] = []
    used_aliases: set[str] = set()
    checked = 0
    for cls, mine in ours.items():
        if cls.startswith("_"):
            continue
        checked += 1
        if cls not in theirs:
            problems.append(f"{cls}: в «Сканере» такой схемы больше нет")
            continue
        real = theirs[cls]
        for name in real.keys() - mine.keys():
            problems.append(f"{cls}.{name}: поле есть в «Сканере» ({real[name]}), но нет в копии")
        for name in mine.keys() - real.keys():
            problems.append(f"{cls}.{name}: поле есть в копии, но его нет в «Сканере»")
        for name in mine.keys() & real.keys():
            if mine[name] != real[name]:
                problems.append(f"{cls}.{name}: тип в копии {mine[name]}, в «Сканере» {real[name]}")
            used_aliases |= _names(real[name]) & their_aliases.keys()
    for alias in sorted(used_aliases):
        if our_aliases.get(alias) != their_aliases[alias]:
            problems.append(f"{alias}: в копии {our_aliases.get(alias, 'нет')}, в «Сканере» {their_aliases[alias]}")
    if not checked:
        problems.append("в копии не найдено ни одной схемы")
    return sorted(problems)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        scanner_src = Path(argv[0]).read_text(encoding="utf-8")
    except OSError as e:
        print(f"Не удалось прочитать схемы «Сканера»: {e}", file=sys.stderr)
        return 2
    problems = compare(CONTRACT.read_text(encoding="utf-8"), scanner_src)
    if problems:
        print(f"Копия схем разошлась со «Сканером» ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        print("Обновите backend/tests/scanner_contract.py, мок и фикстуру (app/integrations/scanner).")
        return 1
    print("Копия схем совпадает со «Сканером».")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
