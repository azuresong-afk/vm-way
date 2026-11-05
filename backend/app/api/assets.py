"""Активы и группы активов «Сканера» (задача 2.2): чтение и синхронизация по кнопке."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.common import paginate
from app.api.tickets import OPEN_STATUSES
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import Asset, AssetGroup, AssetGroupMember, SourceLink, Ticket, TicketHost
from app.rbac import Perm
from app.services import assets as svc

router = APIRouter(tags=["assets"])


def _open_tickets_by_host(db: Session, project_id: str, hosts: list[str]) -> dict[str, int]:
    if not hosts:
        return {}
    return dict(
        db.execute(
            select(TicketHost.host, func.count(func.distinct(TicketHost.ticket_id)))
            .join(Ticket, Ticket.id == TicketHost.ticket_id)
            .where(
                Ticket.project_id == project_id,
                Ticket.status.in_(OPEN_STATUSES),
                TicketHost.status != "confirmed",
                TicketHost.host.in_(hosts),
            )
            .group_by(TicketHost.host)
        ).all()
    )


def asset_out(a: Asset, open_tickets: int = 0) -> dict:
    return {
        "id": a.id,
        "address": a.address,
        "hostname": a.hostname,
        "owner": a.owner,
        "criticality": a.criticality,
        "tags": a.tags or [],
        "groups": [g.name for g in a.groups],
        "os_family": a.os_family,
        "os_guess": a.os_guess,
        "engagement_id": a.engagement_id,
        "scanner_asset_id": a.scanner_asset_id,
        "open_tickets": open_tickets,
        "synced_at": a.synced_at,
    }


@router.get("/projects/{project_id}/assets")
def list_assets(
    project_id: str,
    response: Response,
    group: str | None = Query(default=None, max_length=128),
    tag: str | None = Query(default=None, max_length=64),
    owner: str | None = Query(default=None, max_length=256),
    criticality: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    q: str | None = Query(default=None, max_length=200),
    limit: int = 100,
    offset: int = 0,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    get_project(db, project_id, p)
    stmt = select(Asset).where(Asset.project_id == project_id).options(selectinload(Asset.groups))
    if group:
        stmt = stmt.where(
            Asset.id.in_(
                select(AssetGroupMember.asset_id)
                .join(AssetGroup, AssetGroup.id == AssetGroupMember.group_id)
                .where(AssetGroup.project_id == project_id, AssetGroup.name == group)
            )
        )
    if owner:
        stmt = stmt.where(Asset.owner == owner)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Asset.address.ilike(like), Asset.hostname.ilike(like), Asset.owner.ilike(like)))
    if tag:
        # Теги — JSON-список; фильтр по тегу — в Python (активов в проекте немного).
        rows = [a for a in db.scalars(stmt.order_by(Asset.address)) if tag.strip().lower() in (a.tags or [])]
        response.headers["X-Total-Count"] = str(len(rows))
        offset, limit = max(0, offset), max(1, min(limit, 500))
        rows = rows[offset : offset + limit]
    else:
        rows = paginate(db, stmt.order_by(Asset.address), response, limit, offset)
    counts = _open_tickets_by_host(db, project_id, [a.address for a in rows])
    return [asset_out(a, counts.get(a.address, 0)) for a in rows]


@router.get("/projects/{project_id}/asset-facets")
def asset_facets(project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    """Группы, теги и владельцы активов проекта — для фильтров, правил назначения и окон.

    У группы — число активов и число открытых заявок, у которых хоть один хост в группе."""
    get_project(db, project_id, p)
    groups = db.execute(
        select(AssetGroup.name, func.count(AssetGroupMember.asset_id))
        .outerjoin(AssetGroupMember, AssetGroupMember.group_id == AssetGroup.id)
        .where(AssetGroup.project_id == project_id)
        .group_by(AssetGroup.name)
        .order_by(AssetGroup.name)
    ).all()
    group_tickets = dict(
        db.execute(
            select(AssetGroup.name, func.count(func.distinct(Ticket.id)))
            .join(AssetGroupMember, AssetGroupMember.group_id == AssetGroup.id)
            .join(Asset, Asset.id == AssetGroupMember.asset_id)
            .join(TicketHost, TicketHost.host == Asset.address)
            .join(Ticket, Ticket.id == TicketHost.ticket_id)
            .where(
                AssetGroup.project_id == project_id,
                Ticket.project_id == project_id,
                Ticket.status.in_(OPEN_STATUSES),
            )
            .group_by(AssetGroup.name)
        ).all()
    )
    tags: dict[str, int] = {}
    owners: dict[str, int] = {}
    crit: dict[str, int] = {}
    total = 0
    last = None
    for a_tags, owner, c, synced in db.execute(
        select(Asset.tags, Asset.owner, Asset.criticality, Asset.synced_at).where(Asset.project_id == project_id)
    ):
        total += 1
        last = synced if last is None or synced > last else last
        for t in a_tags or []:
            tags[t] = tags.get(t, 0) + 1
        if owner:
            owners[owner] = owners.get(owner, 0) + 1
        crit[c] = crit.get(c, 0) + 1
    return {
        "total": total,
        "synced_at": last,
        "groups": [{"name": n, "assets": c, "open_tickets": group_tickets.get(n, 0)} for n, c in groups],
        "tags": [{"name": k, "assets": v} for k, v in sorted(tags.items())],
        "owners": [{"name": k, "assets": v} for k, v in sorted(owners.items())],
        "criticality": {c: crit.get(c, 0) for c in svc.CRITICALITY},
    }


@router.post("/projects/{project_id}/assets/sync")
def sync_assets(project_id: str, p: Principal = Depends(require(Perm.IMPORT)), db: Session = Depends(get_db)) -> dict:
    """Обновить активы и группы из «Сканера» по всем привязкам проекта."""
    get_project(db, project_id, p)
    links = db.scalar(select(func.count()).select_from(SourceLink).where(SourceLink.project_id == project_id))
    if not links:
        raise HTTPException(409, "Проект не привязан к «Сканеру»")
    out = svc.sync_project(db, project_id, actor=p.user, ip=p.ip)
    db.commit()
    if len(out["errors"]) == links:
        raise HTTPException(502, "; ".join(e["error"] for e in out["errors"]))
    return out
