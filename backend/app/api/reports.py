"""Отчёт о ходе устранения (задача 3.1): `GET /projects/{id}/report?format=html|pdf|docx|json`.

Право — `view`: отчёты доступны и наблюдателю (представитель заказчика, аудитор). Каждая выгрузка файла пишется
в журнал аудита: кто, какой проект, формат и период; предпросмотр (`download=0`) — нет.
"""

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import Principal, get_project, require
from app.rbac import Perm
from app.reports.model import VARIANTS, ReportError, build_report, make_period
from app.reports.render import CONTENT_TYPES, ReportFormat, ReportRenderer, filename
from app.services.windows import DEFAULT_TZ

router = APIRouter(tags=["reports"])


@router.get("/projects/{project_id}/report")
def project_report(
    project_id: str,
    format: ReportFormat = Query(default=ReportFormat.HTML),  # noqa: A002 — имя параметра как у «Сканера»
    variant: str = Query(default="full", pattern="^(full|brief)$"),
    date_from: date | None = Query(default=None, alias="from"),
    date_to: date | None = Query(default=None, alias="to"),
    tz: str = Query(default=DEFAULT_TZ, max_length=64),
    download: bool = Query(default=True),
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> Response:
    """Отчёт за период: что было, что закрыто и подтверждено, что осталось, по исполнителям и группам активов.

    Период по умолчанию — 90 дней до сегодняшнего дня; границы — по часовому поясу `tz`."""
    project = get_project(db, project_id, p)
    try:
        period = make_period(date_from, date_to, tz)
        data = build_report(db, project, period, variant=variant, author=p.user)
    except ReportError as e:
        raise HTTPException(e.code, e.message)
    try:
        body = ReportRenderer().render(data, format)
    except RuntimeError as e:  # нет WeasyPrint/Pango — PDF недоступен, остальное работает
        raise HTTPException(503, str(e))
    # В журнал — выгрузки файлов. Предпросмотр на экране «Отчёты» (download=0) — обычный просмотр, как сводка.
    if download:
        audit.record(
            db,
            p.user,
            "report.export",
            object_type="project",
            object_id=project.id,
            project_id=project.id,
            ip=p.ip,
            details={
                "format": format.value,
                "variant": variant,
                "from": period.date_from.isoformat(),
                "to": period.date_to.isoformat(),
                "timezone": tz,
            },
        )
        db.commit()
    name = filename(data, format)
    disposition = "attachment" if download else "inline"
    return Response(
        body,
        media_type=CONTENT_TYPES[format],
        headers={
            "Content-Disposition": f'{disposition}; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            # HTML-отчёт открывается сам по себе: без скриптов и внешних ресурсов.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        },
    )


@router.get("/report-meta")
def report_meta(p: Principal = Depends(require(Perm.VIEW))) -> dict:
    """Что умеет отчёт: форматы, варианты, часовой пояс по умолчанию."""
    return {
        "formats": [{"id": f.value, "label": f.value.upper()} for f in ReportFormat],
        "variants": [{"id": k, "label": v} for k, v in VARIANTS.items()],
        "timezone": DEFAULT_TZ,
        "deadlines": False,
    }
