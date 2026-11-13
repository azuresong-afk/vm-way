"""Рендер отчёта о ходе устранения: HTML (Jinja2) → PDF (WeasyPrint), DOCX (python-docx), JSON.

Подход — как у «Сканера» (`scanner/reporting/render.py`): один словарь данных из `model.build_report`,
графики — одна геометрия (`charts`) в виде inline-SVG для HTML/PDF и PNG для DOCX.

Безопасность: названия заявок, хосты, обоснования исключений и имена приходят из недоверенных данных —
HTML экранируется (autoescape), WeasyPrint не загружает внешние ресурсы, из DOCX вырезаются недопустимые
в XML символы.
"""

from __future__ import annotations

import json
import logging
import re
from enum import StrEnum
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from app.reports import charts as ch
from app.reports.charts import SEVERITY_HEX, Scene
from app.reports.model import SEVERITY_LABELS
from app.services.workflow import SEVERITIES

TEMPLATES_DIR = Path(__file__).parent / "templates"
# WeasyPrint через fontTools пишет в журнал каждую операцию со шрифтами — оставляем только предупреждения.
logging.getLogger("fontTools").setLevel(logging.WARNING)

DOCX_FONT = "Calibri"
INK, INK_2, MUTED, FAINT = "#101828", "#344054", "#667085", "#98a2b3"
LINE, PANEL, ACCENT, ACCENT_2 = "#eaecf0", "#f9fafb", "#1d2b4f", "#3e4c7a"
GOOD = "#067647"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"


CONTENT_TYPES: dict[ReportFormat, str] = {
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
    ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ReportFormat.JSON: "application/json",
}

# Символы, недопустимые в XML 1.0 (python-docx на них падает).
_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _x(text: object) -> str:
    return _XML_BAD.sub("�", "" if text is None else str(text))


def _deny_fetch(url: str, *args, **kwargs):
    raise ValueError(f"загрузка внешних ресурсов в отчёт запрещена: {url}")


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(SEVERITY_LABELS=SEVERITY_LABELS, SEVERITY_HEX=SEVERITY_HEX)
    return env


def build_charts(r: dict) -> dict[str, Scene]:
    v = r["totals"]["vulns"]
    out: dict[str, Scene] = {
        "waterfall": ch.waterfall(v["start"], v["fixed"], v["appeared"], v["regression"]),
        "severity": ch.severity_donut({s["severity"]: s["end"] for s in r["by_severity"]}),
        "weeks": ch.weekly_flow(r["weeks"]),
    }
    if r["top_hosts"]:
        out["hosts"] = ch.stacked_bars(
            "hosts",
            "Хосты с наибольшим числом открытых уязвимостей",
            [(h["host"], h["by_severity"]) for h in r["top_hosts"]],
            width=520,
            label_w=130,
        )
    people = [p for p in r["assignees"] if p["open"]]
    if people:
        out["assignees"] = ch.stacked_bars(
            "assignees",
            "Открытые заявки по исполнителям и уровням",
            [(p["name"], p["by_severity"]) for p in people[:12]],
            width=680,
            label_w=170,
        )
    return out


def filename(r: dict, fmt: ReportFormat | str) -> str:
    """Имя файла только из безопасных символов: vm-report-<проект>-<с>-<по>.<формат>."""
    slug = re.sub(r"[^0-9A-Za-z_-]+", "-", r["context"]["project"]["id"]).strip("-")[:40] or "project"
    p = r["context"]["period"]
    return f"vm-report-{slug}-{p['from']}-{p['to']}.{ReportFormat(fmt).value}"


class ReportRenderer:
    def render(self, r: dict, fmt: ReportFormat | str) -> bytes:
        fmt = ReportFormat(fmt)
        if fmt is ReportFormat.HTML:
            return self.render_html(r).encode("utf-8")
        if fmt is ReportFormat.PDF:
            return self.render_pdf(r)
        if fmt is ReportFormat.DOCX:
            return self.render_docx(r)
        return json.dumps(r, ensure_ascii=False, indent=2).encode("utf-8")

    # --- HTML / PDF ---------------------------------------------------------
    def render_html(self, r: dict) -> str:
        # SVG собран из экранированных строк (charts.py) — помечаем как безопасный.
        charts = {k: Markup(s.to_svg()) for k, s in build_charts(r).items()}  # noqa: S704
        return _env().get_template("report.html.j2").render(r=r, c=r["context"], charts=charts)

    def render_pdf(self, r: dict) -> bytes:
        try:
            from weasyprint import HTML  # тяжёлая зависимость (pango) — лениво
        except (ImportError, OSError) as e:
            raise RuntimeError("PDF недоступен: нужен WeasyPrint и системные библиотеки Pango") from e
        return HTML(string=self.render_html(r), url_fetcher=_deny_fetch).write_pdf()

    # --- DOCX ---------------------------------------------------------------
    def render_docx(self, r: dict) -> bytes:  # noqa: C901 — линейная вёрстка документа
        from docx import Document
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.enum.text import WD_BREAK
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Cm, Pt, RGBColor

        def rgb(hex_color: str) -> RGBColor:
            return RGBColor.from_string(hex_color.lstrip("#").upper())

        doc = Document()
        for sec in doc.sections:
            sec.left_margin = sec.right_margin = Cm(2.0)
            sec.top_margin, sec.bottom_margin = Cm(2.0), Cm(1.8)
        style = doc.styles["Normal"]
        style.font.name = DOCX_FONT
        style.font.size = Pt(10)
        style.font.color.rgb = rgb(INK_2)
        style.paragraph_format.space_after = Pt(4)
        for name, size in (("Title", 26), ("Heading 1", 16), ("Heading 2", 12.5)):
            st = doc.styles[name]
            st.font.name = DOCX_FONT
            st.font.size = Pt(size)
            st.font.bold = True
            st.font.color.rgb = rgb(INK)
            st.element.rPr.rFonts.set(qn("w:asciiTheme"), DOCX_FONT)
            st.paragraph_format.space_before = Pt(14 if name != "Title" else 0)
            st.paragraph_format.space_after = Pt(6)

        page_cm = 17.0
        scenes = build_charts(r) if ch.png_available() else {}
        c = r["context"]
        v = r["totals"]["vulns"]
        full = c["variant"] == "full"

        def shade(cell, fill: str) -> None:
            pr = cell._tc.get_or_add_tcPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), fill.lstrip("#"))
            pr.append(shd)

        def hairlines(t) -> None:
            borders = OxmlElement("w:tblBorders")
            for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
                b = OxmlElement(f"w:{edge}")
                if edge in ("left", "right", "insideV"):
                    b.set(qn("w:val"), "nil")
                else:
                    b.set(qn("w:val"), "single")
                    b.set(qn("w:sz"), "4")
                    b.set(qn("w:color"), LINE.lstrip("#"))
                borders.append(b)
            t._tbl.tblPr.append(borders)

        def spacer(pt: float = 4) -> None:
            p = doc.add_paragraph()
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.space_before = Pt(0)
            p.add_run().font.size = Pt(pt)

        def small(par, text: str, color: str = MUTED, size: float = 8.5, bold: bool = False):
            run = par.add_run(_x(text))
            run.font.size = Pt(size)
            run.font.color.rgb = rgb(color)
            run.bold = bold
            return run

        def table(header: list[str], rows: list[list[object]], widths: list[float], num_from: int | None = None):
            t = doc.add_table(rows=1, cols=len(header))
            t.alignment = WD_TABLE_ALIGNMENT.CENTER
            hairlines(t)
            for cell, h in zip(t.rows[0].cells, header, strict=True):
                cell.text = ""
                shade(cell, PANEL)
                small(cell.paragraphs[0], h.upper(), MUTED, 7.5, bold=True)
                if num_from is not None and header.index(h) >= num_from:
                    cell.paragraphs[0].alignment = 2
            for row in rows:
                cells = t.add_row().cells
                for j, (cell, val) in enumerate(zip(cells, row, strict=True)):
                    cell.text = ""
                    if isinstance(val, tuple) and val and val[0] == "sev":
                        run = cell.paragraphs[0].add_run("● " + SEVERITY_LABELS[val[1]])
                        run.bold = True
                        run.font.size = Pt(8.5)
                        run.font.color.rgb = rgb(SEVERITY_HEX[val[1]])
                        continue
                    if isinstance(val, tuple) and val and val[0] == "two":
                        run = cell.paragraphs[0].add_run(_x(val[1]))
                        run.font.size = Pt(9)
                        if val[2]:
                            small(cell.add_paragraph(), val[2], MUTED, 7.5)
                        continue
                    run = cell.paragraphs[0].add_run(_x(val))
                    run.font.size = Pt(9)
                    if num_from is not None and j >= num_from:
                        cell.paragraphs[0].alignment = 2
                        if val in (0, "0"):
                            run.font.color.rgb = rgb(FAINT)
            t.autofit = False
            for col, w in zip(t.columns, widths, strict=True):
                col.width = Cm(w)
            for row in t.rows:
                for cell, w in zip(row.cells, widths, strict=True):
                    cell.width = Cm(w)
            spacer()
            return t

        def picture(key: str, width_cm: float) -> None:
            if key in scenes:
                doc.add_picture(BytesIO(scenes[key].to_png()), width=Cm(width_cm))
                doc.paragraphs[-1].alignment = 1

        def heading(num: int, text: str, page_break: bool = True) -> None:
            if page_break:
                doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
            h = doc.add_heading(level=1)
            run = h.add_run(f"{num:02d}  ")
            run.font.color.rgb = rgb(ACCENT_2)
            h.add_run(_x(text))

        def kpis(items: list[tuple[str, str, str | None]]) -> None:
            t = doc.add_table(rows=1, cols=len(items))
            hairlines(t)
            for cell, (label, value, color) in zip(t.rows[0].cells, items, strict=True):
                cell.text = ""
                shade(cell, PANEL)
                small(cell.paragraphs[0], label.upper(), MUTED, 7, bold=True)
                vr = cell.add_paragraph().add_run(_x(value))
                vr.bold = True
                vr.font.size = Pt(17)
                vr.font.color.rgb = rgb(color or INK)
            spacer()

        def lead(text: str) -> None:
            small(doc.add_paragraph(), text, MUTED, 9)

        # Обложка
        spacer(60)
        small(
            doc.add_paragraph(),
            "УСТРАНЕНИЕ УЯЗВИМОСТЕЙ · ОТЧЁТ О ХОДЕ РАБОТ" + (" · КРАТКАЯ ВЕРСИЯ" if not full else ""),
            ACCENT_2,
            8,
            bold=True,
        )
        doc.add_paragraph(style="Title").add_run(_x(c["title"])).font.color.rgb = rgb(ACCENT)
        cr = doc.add_paragraph().add_run(_x(c["project"]["client"] or c["project"]["name"]))
        cr.bold = True
        cr.font.size = Pt(14)
        cr.font.color.rgb = rgb(INK)
        meta = [f"Проект: {c['project']['name']}"]
        if c["project"]["contract_ref"]:
            meta.append(f"Договор: {c['project']['contract_ref']}")
        meta.append(f"Период: {c['period']['label']}")
        meta.append(f"Сформирован: {c['generated_local']} ({c['period']['timezone']})")
        if c["author"]:
            meta.append(f"Сформировал: {c['author']}")
        small(doc.add_paragraph(), " · ".join(meta), MUTED, 9)
        spacer(24)
        kpis(
            [
                ("Открыто на начало", str(v["start"]), None),
                ("Закрыто и подтверждено", str(v["fixed"]), GOOD),
                ("Появилось", str(v["appeared"]), None),
                ("Открыто на конец", str(v["end"]), ACCENT),
            ]
        )
        spacer(80)
        small(
            doc.add_paragraph(),
            "Конфиденциально. Отчёт сформирован по данным повторных проверок «Сканера» и предназначен "
            "только для заказчика и исполнителей работ.",
            FAINT,
            8,
        )

        # 1. Резюме
        heading(1, "Резюме")
        delta = v["end"] - v["start"]
        kpis(
            [
                ("На начало периода", str(v["start"]), None),
                ("Закрыто и подтверждено", str(v["fixed"]), GOOD),
                ("Появилось", str(v["appeared"]), None),
                ("На конец", f"{v['end']} ({delta:+d})".replace("-", "−") if delta else str(v["end"]), ACCENT),
            ]
        )
        t = r["totals"]
        kpis(
            [
                ("Заявок подтверждено", str(t["tickets_verified"]), None),
                ("Заявок осталось", f"{t['tickets_open']} из {t['tickets_total']}", None),
                ("Исключений", str(t["tickets_exceptions"]), None),
                ("Не проверено хостов", str(t["hosts_unverified"]), "#c4320a" if t["hosts_unverified"] else None),
            ]
        )
        doc.add_heading("Главное", level=2)
        for point in r["key_points"]:
            doc.add_paragraph(_x(point), style="List Bullet")
        if c["tickets_as_of_now"]:
            lead(
                "Период закончился раньше даты формирования. Движение уязвимостей посчитано на границы периода, "
                f"а списки заявок, исполнители и исключения показаны на {c['generated_local']}."
            )
        picture("waterfall", 10.0)
        picture("severity", 10.0)
        doc.add_heading("По уровням опасности", level=2)
        table(
            ["Уровень", "На начало", "Закрыто", "Появилось", "Регрессии", "На конец"],
            [
                [("sev", s["severity"]), s["start"], s["fixed"], s["appeared"], s["regression"], s["end"]]
                for s in r["by_severity"]
            ]
            + [["Всего", v["start"], v["fixed"], v["appeared"], v["regression"], v["end"]]],
            [4.5, 2.5, 2.5, 2.5, 2.5, 2.5],
            num_from=1,
        )
        doc.add_heading("По неделям", level=2)
        picture("weeks", page_cm)

        # 2. Что закрыто
        heading(2, "Что закрыто и подтверждено")
        lead(
            "Уязвимость считается закрытой, только когда прогон «Сканера» полностью проверил хост и модуль и не "
            "нашёл её. Если хост был недоступен или проверка неполная, результат — «не проверено»."
        )
        doc.add_heading("Прогоны за период", level=2)
        if r["runs"]:
            table(
                ["Дата", "Прогон", "Вид", "Закрыто", "Появилось", "Регрессии"],
                [
                    [
                        x["finished_local"],
                        ("two", x["name"] or "Прогон", f"№{x['scanner_run_id']} «Сканера»"),
                        x["kind_label"],
                        x["fixed"],
                        x["appeared"],
                        x["regression"],
                    ]
                    for x in r["runs"]
                ],
                [2.2, 5.6, 3.0, 2.0, 2.1, 2.1],
                num_from=3,
            )
        else:
            lead("За период прогонов не было.")
        if full:
            doc.add_heading("Подтверждённые заявки", level=2)
            if r["verified"]:
                table(
                    ["№", "Заявка", "Уровень", "Исполнитель", "Хостов", "Подтверждение"],
                    [
                        [
                            x["id"],
                            ("two", x["title"], x["kind_label"] + (f" · {x['os']}" if x["os"] else "")),
                            ("sev", x["severity"]),
                            x["assignee"] or "—",
                            f"{x['hosts_confirmed']}/{x['hosts']}",
                            (
                                "two",
                                x["closed_local"],
                                f"прогон №{x['evidence']['scanner_run_id']}" if x["evidence"]["scanner_run_id"] else "",
                            ),
                        ]
                        for x in r["verified"]
                    ],
                    [1.0, 6.4, 2.4, 2.8, 1.6, 2.8],
                )
            else:
                lead("За период подтверждённых заявок нет.")

        # 3. Что осталось
        heading(3, "Что осталось")
        picture("hosts", 13.0)
        if full:
            if r["remaining"]:
                table(
                    ["№", "Заявка", "Уровень", "Статус", "Исполнитель", "Открыто"],
                    [
                        [
                            x["id"],
                            (
                                "two",
                                x["title"] + (" · регрессия" if x["is_regression"] else ""),
                                x["kind_label"]
                                + (f" · {x['os']}" if x["os"] else "")
                                + (f" · не проверено хостов: {x['hosts_unverified']}" if x["hosts_unverified"] else ""),
                            ),
                            ("sev", x["severity"]),
                            x["status_label"],
                            x["assignee"] or "—",
                            x["open_vulns"],
                        ]
                        for x in r["remaining"]
                    ],
                    [1.0, 6.6, 2.4, 2.8, 2.6, 1.6],
                    num_from=5,
                )
            else:
                lead("Открытых заявок нет.")
        else:
            lead(f"Открытых заявок: {t['tickets_open']}. Список заявок — в полной версии отчёта.")

        # 4. Исполнители
        heading(4, "По исполнителям")
        lead("Открытые заявки — по текущему исполнителю; «Подтверждено» и «Закрыто уязв.» — за период.")
        picture("assignees", page_cm)
        if r["assignees"]:
            table(
                [
                    "Исполнитель",
                    "Открыто",
                    "В работе",
                    "Ждут проверки",
                    "Открыто уязв.",
                    "Подтверждено",
                    "Закрыто уязв.",
                ],
                [
                    [
                        p["name"],
                        p["open"],
                        p["in_work"],
                        p["awaiting_check"],
                        p["open_vulns"],
                        p["verified"],
                        p["fixed_vulns"],
                    ]
                    for p in r["assignees"]
                ],
                [4.4, 1.8, 1.8, 2.2, 2.2, 2.4, 2.2],
                num_from=1,
            )

        # 5. Группы
        heading(5, "По группам активов", page_break=False)
        lead(
            "Группы — из «Сканера». Хост из нескольких групп учитывается в каждой; "
            "хосты без группы — отдельной строкой."
        )
        if r["groups"]:
            table(
                ["Группа", "Хостов", "На начало", "Закрыто", "Появилось", "Регрессии", "На конец"],
                [
                    [g["name"], g["hosts"], g["start"], g["fixed"], g["appeared"], g["regression"], g["end"]]
                    for g in r["groups"]
                ],
                [4.6, 1.8, 2.1, 2.1, 2.2, 2.1, 2.1],
                num_from=1,
            )

        # 6. Исключения
        heading(6, "Исключения", page_break=False)
        lead(
            "Действующие решения не устранять уязвимость: принятый риск с обоснованием и утверждающим, ложные "
            "срабатывания. Дата пересмотра — когда решение нужно подтвердить заново."
        )
        if r["exceptions"]:
            table(
                ["Заявка", "Вид", "Обоснование", "Утвердил", "Пересмотр"],
                [
                    [
                        ("two", f"№{e['ticket_id']} {e['ticket_title']}", SEVERITY_LABELS[e["severity"]]),
                        e["kind_label"],
                        ("two", e["reason"], f"Меры: {e['measures']}" if e["measures"] else ""),
                        ("two", e["approver"] or "—", e["approved_local"]),
                        e["review_local"] or "—",
                    ]
                    for e in r["exceptions"]
                ],
                [4.6, 2.6, 5.0, 2.6, 2.2],
            )
        else:
            lead("Действующих исключений нет.")

        spacer(10)
        small(
            doc.add_paragraph(),
            "Как считается: состояние уязвимости на дату — по последнему событию прогонов «Сканера» до этой даты "
            "(нашёл, подтвердил исправление, нашёл снова). На конец периода = на начало + появилось + регрессии − "
            f"закрыто. Границы периода — по часовому поясу {c['period']['timezone']}. "
            "Сроки устранения в отчёт не включены.",
            MUTED,
            8,
        )

        buf = BytesIO()
        doc.save(buf)
        return buf.getvalue()


__all__ = ["CONTENT_TYPES", "ReportFormat", "ReportRenderer", "SEVERITIES", "build_charts", "filename"]
