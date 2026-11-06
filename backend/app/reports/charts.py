"""Графики отчёта (задача 3.1): одна геометрия -> inline-SVG (HTML/PDF) и PNG (DOCX).

Примитивы (`Scene`, `Rect`, `Line`, `Text`, `Arc`) и их отрисовка перенесены из «Сканера»
(`scanner/reporting/charts.py`) один в один, чтобы отчёты продуктов выглядели одинаково. Отличие — уровни
опасности здесь строки, а не перечисление «Сканера».

Строки (хосты, имена исполнителей и групп) приходят из недоверенных данных — в SVG они экранируются.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import cache
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from app.reports.model import SEVERITY_LABELS
from app.services.workflow import SEVERITIES

FONT = "Inter, DejaVu Sans"

# Цвета уровней — как в отчётах «Сканера».
SEVERITY_HEX: dict[str, str] = {
    "critical": "#b42318",
    "high": "#e8590c",
    "medium": "#d29a0b",
    "low": "#2f6fb3",
    "info": "#a0a8b5",
}
FIXED_HEX, APPEARED_HEX, REGRESSION_HEX = "#067647", "#e8590c", "#b42318"
INK, MUTED, GRID, SURFACE = "#101828", "#667085", "#f2f4f7", "#ffffff"
NEUTRAL, ACCENT, AXIS = "#d0d5dd", "#1d2b4f", "#d0d5dd"


# --- примитивы ------------------------------------------------------------------


@dataclass(slots=True)
class Rect:
    x: float
    y: float
    w: float
    h: float
    fill: str
    round_end: str | None = None  # "right" | "top" — скруглённый конец данных
    title: str | None = None


@dataclass(slots=True)
class Line:
    x1: float
    y1: float
    x2: float
    y2: float
    stroke: str = GRID
    width: float = 1


@dataclass(slots=True)
class Text:
    x: float
    y: float  # базовая линия
    text: str
    size: float = 11
    fill: str = INK
    anchor: str = "start"  # start | middle | end
    bold: bool = False


@dataclass(slots=True)
class Arc:
    """Сектор кольца; углы в градусах по часовой от 12 часов."""

    cx: float
    cy: float
    r: float
    r_inner: float
    a0: float
    a1: float
    fill: str
    title: str | None = None


@dataclass(slots=True)
class Scene:
    key: str
    width: int
    height: int
    label: str  # aria-label: что изображено
    shapes: list = field(default_factory=list)

    def add(self, *shapes) -> None:
        self.shapes.extend(shapes)

    # --- SVG ---------------------------------------------------------------------
    def to_svg(self) -> str:
        out = [
            (
                f'<svg xmlns="http://www.w3.org/2000/svg" class="chart" '
                f'data-chart="{self.key}" viewBox="0 0 {self.width} {self.height}" '
                f'width="{self.width}" height="{self.height}" role="img" '
                f'aria-label="{_attr(self.label)}" '
                f'font-family="{FONT}, Arial, sans-serif">'
            )
        ]
        out.extend(_svg_shape(s) for s in self.shapes)
        out.append("</svg>")
        return "".join(out)

    # --- PNG ---------------------------------------------------------------------
    def to_png(self, scale: int = 3) -> bytes:
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (self.width * scale, self.height * scale), SURFACE)
        d = ImageDraw.Draw(img)
        k = scale
        texts = []
        for s in self.shapes:
            if isinstance(s, Rect):
                _png_rect(d, s, k)
            elif isinstance(s, Line):
                d.line([(s.x1 * k, s.y1 * k), (s.x2 * k, s.y2 * k)], fill=s.stroke, width=max(1, round(s.width * k)))
            elif isinstance(s, Arc):
                box = [(s.cx - s.r) * k, (s.cy - s.r) * k, (s.cx + s.r) * k, (s.cy + s.r) * k]
                # Pillow: 0° — 3 часа, по часовой; у нас 0° — 12 часов
                d.pieslice(box, s.a0 - 90, s.a1 - 90, fill=s.fill, outline=SURFACE, width=2 * k)
            elif isinstance(s, Text):
                texts.append(s)
        # «дырка» кольца — после всех секторов; текст — поверх всего
        for s in self.shapes:
            if isinstance(s, Arc):
                ri = s.r_inner * k
                d.ellipse([s.cx * k - ri, s.cy * k - ri, s.cx * k + ri, s.cy * k + ri], fill=SURFACE)
        for s in texts:
            anchor = {"start": "ls", "middle": "ms", "end": "rs"}[s.anchor]
            d.text((s.x * k, s.y * k), s.text, fill=s.fill, font=_font(round(s.size * k), s.bold), anchor=anchor)
        buf = BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()


def _attr(v: str) -> str:
    return escape(v, {'"': "&quot;"})


def _svg_title(t: str | None) -> str:
    return f"<title>{escape(t)}</title>" if t else ""


def _svg_shape(s) -> str:
    if isinstance(s, Rect):
        if s.w <= 0 or s.h <= 0:
            return ""
        r = min(4.0, s.w / 2, s.h / 2) if s.round_end else 0
        if s.round_end == "right":
            x, y, w, h = s.x, s.y, s.w, s.h
            d = (
                f"M{x:.1f},{y:.1f}H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
                f"V{y + h - r:.1f}Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f}"
                f"H{x:.1f}Z"
            )
        elif s.round_end == "top":
            x, y, w, h = s.x, s.y, s.w, s.h
            d = (
                f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
                f"H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
                f"V{y + h:.1f}Z"
            )
        else:
            return (
                f'<rect x="{s.x:.1f}" y="{s.y:.1f}" width="{s.w:.1f}" '
                f'height="{s.h:.1f}" fill="{s.fill}">{_svg_title(s.title)}</rect>'
            )
        return f'<path d="{d}" fill="{s.fill}">{_svg_title(s.title)}</path>'
    if isinstance(s, Line):
        return (
            f'<line x1="{s.x1:.1f}" y1="{s.y1:.1f}" x2="{s.x2:.1f}" y2="{s.y2:.1f}" '
            f'stroke="{s.stroke}" stroke-width="{s.width}"/>'
        )
    if isinstance(s, Text):
        weight = ' font-weight="bold"' if s.bold else ""
        return (
            f'<text x="{s.x:.1f}" y="{s.y:.1f}" font-size="{s.size}" fill="{s.fill}" '
            f'text-anchor="{s.anchor}"{weight}>{escape(s.text)}</text>'
        )
    if isinstance(s, Arc):
        return (
            f'<path d="{_arc_path(s)}" fill="{s.fill}" stroke="{SURFACE}" stroke-width="2">{_svg_title(s.title)}</path>'
        )
    raise TypeError(s)


def _pt(cx: float, cy: float, r: float, a: float) -> tuple[float, float]:
    rad = math.radians(a)
    return cx + r * math.sin(rad), cy - r * math.cos(rad)


def _arc_path(s: Arc) -> str:
    a1 = s.a1 if s.a1 - s.a0 < 360 else s.a0 + 359.99
    large = 1 if a1 - s.a0 > 180 else 0
    x0, y0 = _pt(s.cx, s.cy, s.r, s.a0)
    x1, y1 = _pt(s.cx, s.cy, s.r, a1)
    x2, y2 = _pt(s.cx, s.cy, s.r_inner, a1)
    x3, y3 = _pt(s.cx, s.cy, s.r_inner, s.a0)
    return (
        f"M{x0:.2f},{y0:.2f}A{s.r},{s.r} 0 {large} 1 {x1:.2f},{y1:.2f}"
        f"L{x2:.2f},{y2:.2f}A{s.r_inner},{s.r_inner} 0 {large} 0 {x3:.2f},{y3:.2f}Z"
    )


def _png_rect(d, s: Rect, k: int) -> None:
    if s.w <= 0 or s.h <= 0:
        return
    x0, y0, x1, y1 = s.x * k, s.y * k, (s.x + s.w) * k, (s.y + s.h) * k
    r = min(4.0, s.w / 2, s.h / 2) * k if s.round_end else 0
    if not r:
        d.rectangle([x0, y0, x1, y1], fill=s.fill)
        return
    d.rounded_rectangle([x0, y0, x1, y1], radius=r, fill=s.fill)
    # конец у базовой линии — прямой
    if s.round_end == "right":
        d.rectangle([x0, y0, x0 + r, y1], fill=s.fill)
    else:
        d.rectangle([x0, y1 - r, x1, y1], fill=s.fill)


_FONT_DIRS = ("/usr/share/fonts", "/usr/local/share/fonts", "/Library/Fonts", "C:/Windows/Fonts")


@cache
def _font_path(bold: bool) -> str | None:
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    for root in _FONT_DIRS:
        p = Path(root)
        if p.is_dir():
            for hit in p.rglob(name):
                return str(hit)
    return None


@cache
def _font(size: int, bold: bool):
    from PIL import ImageFont

    path = _font_path(bold) or _font_path(False)
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)  # без кириллицы; DejaVu есть в Docker-образе


def png_available() -> bool:
    try:
        import PIL  # noqa: F401
    except ImportError:
        return False
    return True


# --- вспомогательное -----------------------------------------------------------------


def _scale(v: int) -> tuple[int, int]:
    """Шкала оси: (верх, шаг) — «круглый» шаг, не больше 5 делений."""
    v = max(v, 1)
    mag = 1
    while True:
        for m in (1, 2, 5):
            step = m * mag
            if v / step <= 5:
                return -(-v // step) * step, step
        mag *= 10


def _ticks(top: int, step: int) -> list[int]:
    return list(range(0, top + 1, step))


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _pct(part: int, total: int) -> str:
    return f"{round(100 * part / total)}%" if total else "0%"


def _legend(scene: Scene, x: float, y: float, items: Sequence[tuple[str, str]], gap: float = 12) -> float:
    """Легенда с переносом строк; возвращает базовую линию последней строки."""
    x0 = x
    for label, color in items:
        w = 14 + len(label) * 6.0
        if x > x0 and x + w > scene.width:
            x, y = x0, y + 15
        scene.add(Rect(x, y - 9, 10, 10, color), Text(x + 14, y, label, 10, MUTED))
        x += w + gap
    return y


# --- диаграммы ----------------------------------------------------------------------


def _sev_legend() -> list[tuple[str, str]]:
    return [(SEVERITY_LABELS[s], SEVERITY_HEX[s]) for s in SEVERITIES]


def severity_donut(counts: dict[str, int], caption: str = "открыто") -> Scene:
    """Кольцо: открытые на конец периода по уровням + легенда с числом и долей."""
    total = sum(counts.values())
    sc = Scene("severity", 340, 180, "Открытые уязвимости на конец периода по уровню опасности")
    cx, cy, r, ri = 88, 90, 76, 56
    if total:
        a = 0.0
        for s in SEVERITIES:
            n = counts.get(s, 0)
            if not n:
                continue
            span = 360 * n / total
            sc.add(Arc(cx, cy, r, ri, a, a + span, SEVERITY_HEX[s], f"{SEVERITY_LABELS[s]}: {n} ({_pct(n, total)})"))
            a += span
    else:
        sc.add(Arc(cx, cy, r, ri, 0, 360, GRID, "Открытых уязвимостей нет"))
    sc.add(
        Text(cx, cy + 5, str(total), 26, INK, "middle", bold=True),
        Text(cx, cy + 22, caption, 9, MUTED, "middle"),
    )
    y = 38
    for s in SEVERITIES:
        n = counts.get(s, 0)
        sc.add(
            Rect(186, y - 10, 11, 11, SEVERITY_HEX[s]),
            Text(203, y, SEVERITY_LABELS[s], 10.5, INK),
            Text(316, y, str(n), 10.5, INK, "end", bold=True),
            Text(338, y, _pct(n, total), 9, MUTED, "end"),
        )
        y += 27
    return sc


def stacked_bars(
    key: str, label: str, rows: Sequence[tuple[str, dict[str, int]]], width: int = 520, label_w: int = 150
) -> Scene:
    """Горизонтальные столбцы с разбивкой по уровням (хосты, исполнители)."""
    band, bar, bottom = 26, 13, 22
    sc = Scene(key, width, 0, label)
    top_pad = _legend(sc, 4, 12, _sev_legend()) + 14
    base_y = top_pad + band * max(len(rows), 1)
    sc.height = round(base_y + bottom)
    plot_w = width - label_w - 34
    max_chars = max(6, int((label_w - 10) / 6.4))
    peak, step = _scale(max((sum(c.values()) for _, c in rows), default=0))
    for t in _ticks(peak, step):
        x = label_w + plot_w * t / peak
        sc.add(Line(x, top_pad - 4, x, base_y), Text(x, base_y + 14, str(t), 9, MUTED, "middle"))
    for i, (name, counts) in enumerate(rows):
        y = top_pad + i * band + (band - bar) / 2
        total = sum(counts.values())
        sc.add(Text(label_w - 8, y + bar / 2 + 4, _short(name, max_chars), 10.5, INK, "end"))
        x = label_w
        segs = [s for s in SEVERITIES if counts.get(s)]
        for j, s in enumerate(segs):
            w = plot_w * counts[s] / peak
            last = j == len(segs) - 1
            sc.add(
                Rect(
                    x,
                    y,
                    max(w - (0 if last else 2), 0.5),
                    bar,
                    SEVERITY_HEX[s],
                    "right" if last else None,
                    f"{name} — {SEVERITY_LABELS[s]}: {counts[s]}",
                )
            )
            x += w
        sc.add(Text(x + 5, y + bar / 2 + 4, str(total), 10, INK, bold=True))
    if not rows:
        sc.add(Text(width / 2, top_pad + band / 2 + 4, "Нет данных", 10.5, MUTED, "middle"))
    return sc


def waterfall(start: int, fixed: int, appeared: int, regression: int, width: int = 340) -> Scene:
    """Каскад за период: на начало -> появилось -> регрессии -> закрыто -> на конец.

    Закрытие идёт последним: закрытыми могут быть и уязвимости, появившиеся внутри периода, поэтому
    столбцы не уходят ниже нуля."""
    height = 210
    sc = Scene("waterfall", width, height, "Движение открытых уязвимостей за период")
    peak_v = start + appeared + regression
    end = peak_v - fixed
    steps = [
        ("На начало", 0, start, NEUTRAL, f"Открыто на начало периода: {start}"),
        ("Появилось", start, start + appeared, APPEARED_HEX, f"Появилось: +{appeared}"),
        ("Регрессии", start + appeared, peak_v, REGRESSION_HEX, f"Вернулось после исправления: +{regression}"),
        ("Закрыто", end, peak_v, FIXED_HEX, f"Закрыто и подтверждено: −{fixed}"),
        ("На конец", 0, end, ACCENT, f"Открыто на конец периода: {end}"),
    ]
    left, top, base = 34, 24, height - 26
    plot_w, plot_h = width - left - 8, base - top
    peak, step = _scale(peak_v)
    for t in _ticks(peak, step):
        y = base - plot_h * t / peak
        sc.add(Line(left, y, width - 8, y), Text(left - 6, y + 3, str(t), 9, MUTED, "end"))
    slot = plot_w / len(steps)
    col = min(32, slot * 0.55)
    values = [start, appeared, regression, -fixed, end]
    for i, (name, lo, hi, color, title) in enumerate(steps):
        x = left + slot * i + (slot - col) / 2
        y_hi, y_lo = base - plot_h * hi / peak, base - plot_h * lo / peak
        sc.add(Rect(x, y_hi, col, max(y_lo - y_hi, 0.5 if hi == lo else 0), color, "top" if lo == 0 else None, title))
        val = values[i]
        txt = str(val) if i in (0, 4) else (f"{val:+d}" if val else "0").replace("-", "−")
        sc.add(
            Text(x + col / 2, y_hi - 5, txt, 10, INK, "middle", bold=True),
            Text(x + col / 2, base + 15, name, 9.5, MUTED, "middle"),
        )
        if 0 < i < len(steps) - 1:  # соединитель уровня с предыдущим шагом
            yl = base - plot_h * (hi if i == 3 else lo) / peak
            sc.add(Line(x - (slot - col), yl, x, yl, AXIS, 1))
    sc.add(Line(left, base, width - 8, base, AXIS))
    return sc


def weekly_flow(weeks: Sequence[dict], width: int = 680) -> Scene:
    """Недели периода: появившиеся — вверх от оси, закрытые — вниз; столбцы по уровням от критических."""
    sc = Scene("weeks", width, 0, "Появилось и закрыто по неделям")
    top = _legend(sc, 4, 12, _sev_legend()) + 22
    half = 80
    axis = top + half
    sc.height = round(axis + half + 30)
    left = 34
    plot_w = width - left - 8
    peak_v = max((max(sum(w["opened"].values()), sum(w["closed"].values())) for w in weeks), default=0)
    peak, step = _scale(peak_v)
    for t in _ticks(peak, step):
        dy = half * t / peak
        sc.add(Line(left, axis - dy, width - 8, axis - dy), Text(left - 6, axis - dy + 3, str(t), 9, MUTED, "end"))
        if t:
            sc.add(Line(left, axis + dy, width - 8, axis + dy), Text(left - 6, axis + dy + 3, str(t), 9, MUTED, "end"))
    sc.add(
        Text(left + 2, top - 6, "↑ появилось", 9, MUTED),
        Text(left + 2, axis + half + 12, "↓ закрыто и подтверждено", 9, MUTED),
    )
    n = max(len(weeks), 1)
    slot = plot_w / n
    col = max(2.0, min(22, slot * 0.6))
    label_every = max(1, math.ceil(n / 9))
    for i, w in enumerate(weeks):
        x = left + slot * i + (slot - col) / 2
        day = w["start"][8:10] + "." + w["start"][5:7]
        y = axis
        for s in SEVERITIES:  # вверх: от критических у оси
            c = w["opened"].get(s, 0)
            if c:
                h = half * c / peak
                sc.add(
                    Rect(
                        x,
                        y - h,
                        col,
                        h,
                        SEVERITY_HEX[s],
                        None,
                        f"Неделя с {day} — появилось, {SEVERITY_LABELS[s]}: {c}",
                    )
                )
                y -= h
        y = axis
        for s in SEVERITIES:
            c = w["closed"].get(s, 0)
            if c:
                h = half * c / peak
                sc.add(
                    Rect(x, y, col, h, SEVERITY_HEX[s], None, f"Неделя с {day} — закрыто, {SEVERITY_LABELS[s]}: {c}")
                )
                y += h
        if i % label_every == 0:
            sc.add(Text(x + col / 2, axis + half + 26, day, 9, MUTED, "middle"))
    sc.add(Line(left, axis, width - 8, axis, INK, 1))
    return sc
