"""Активы и группы активов «Сканера» (задача 2.2).

Источник истины — «Сканер» (`GET /engagements/{id}/assets` и `/asset-groups`). «Устранение» держит
копию по ключу `(проект, адрес)` — тот же ключ, что в контракте платформы, — чтобы правила
назначения, фильтр «группа активов» и охват окон работали без обращения к «Сканеру».

Синхронизация идёт при каждом импорте прогона (по его привязке) и по кнопке (по всем привязкам
проекта). Актив, которого больше нет в проекте «Сканера», удаляется. Группы сопоставляются по
имени: одноимённые группы из разных проектов «Сканера» — одна группа. Пустые группы тоже
переносятся — по ним можно заранее настроить правило или окно. Группа, которой больше нет ни в
одном проекте «Сканера», удаляется только полной синхронизацией (по кнопке).
"""

import logging
from collections.abc import Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.db import lock_project, utcnow
from app.integrations.scanner import ScannerClient, ScannerError
from app.models import Asset, AssetGroup, AssetGroupMember, SourceLink, User

log = logging.getLogger("vm.assets")

CRITICALITY = ["critical", "high", "medium", "low"]
CRITICALITY_LABELS = {"critical": "Критичный", "high": "Высокая", "medium": "Средняя", "low": "Низкая"}


def _clean(s: object, n: int) -> str:
    return str(s or "").strip()[:n]


def _group_rows(db: Session, project_id: str, names: Iterable[str]) -> dict[str, AssetGroup]:
    rows = {g.name: g for g in db.scalars(select(AssetGroup).where(AssetGroup.project_id == project_id))}
    now = utcnow()
    for name in names:
        if name not in rows:
            g = AssetGroup(project_id=project_id, name=name, synced_at=now)
            db.add(g)
            rows[name] = g
        else:
            rows[name].synced_at = now
    db.flush()
    return rows


def sync_link(db: Session, link: SourceLink, client: ScannerClient) -> dict:
    """Переносит активы и группы одного проекта «Сканера». Возвращает счётчики и имена групп."""
    raw_assets = client.assets(link.engagement_id)
    raw_groups = client.asset_groups(link.engagement_id)
    group_names = {_clean(g["name"], 128) for g in raw_groups} | {
        _clean(g["name"], 128) for a in raw_assets for g in a.get("groups", [])
    }
    group_names.discard("")
    groups = _group_rows(db, link.project_id, group_names)

    existing = {
        a.address: a
        for a in db.scalars(
            select(Asset).where(Asset.project_id == link.project_id).options(selectinload(Asset.groups))
        )
    }
    now = utcnow()
    seen: set[str] = set()
    stats = {"assets": 0, "created": 0, "updated": 0, "removed": 0, "groups": len(group_names)}
    for a in raw_assets:
        address = _clean(a.get("address"), 64)
        if not address or address in seen:
            continue
        seen.add(address)
        row = existing.get(address)
        if row is None:
            row = Asset(project_id=link.project_id, address=address)
            db.add(row)
            existing[address] = row
            stats["created"] += 1
        else:
            stats["updated"] += 1
        row.source_id = link.source_id
        row.engagement_id = link.engagement_id
        row.scanner_asset_id = int(a["id"])
        row.hostname = _clean(a.get("hostname"), 253)
        row.owner = _clean(a.get("owner"), 256)
        crit = a.get("criticality")
        row.criticality = crit if crit in CRITICALITY else "medium"
        row.tags = sorted({_clean(t, 64).lower() for t in a.get("tags") or [] if _clean(t, 64)})
        row.os_family = _clean(a.get("os_family"), 64)
        row.os_guess = _clean(a.get("os_guess"), 200)
        row.synced_at = now
        row.groups = [groups[n] for n in sorted({_clean(g["name"], 128) for g in a.get("groups", [])}) if n]
        stats["assets"] += 1
    # Актив удалён в «Сканере» — удаляем копию (только те, что пришли из этой привязки).
    for address, row in existing.items():
        if address not in seen and row.source_id == link.source_id and row.engagement_id == link.engagement_id:
            db.delete(row)
            stats["removed"] += 1
    db.flush()
    stats["group_names"] = sorted(group_names)
    return stats


def sync_project(db: Session, project_id: str, *, actor: User | None = None, ip: str = "") -> dict:
    """Полная синхронизация по всем привязкам проекта (кнопка «Обновить из «Сканера»»)."""
    from app.services.importer import client_for

    # Импорт прогона тоже переносит активы и группы — не пересекаемся с ним.
    lock_project(db, project_id)
    links = list(db.scalars(select(SourceLink).where(SourceLink.project_id == project_id)))
    total = {"assets": 0, "created": 0, "updated": 0, "removed": 0, "groups_removed": 0, "errors": []}
    names: set[str] = set()
    ok_links = 0
    for link in links:
        try:
            st = sync_link(db, link, client_for(link.source))
        except ScannerError as e:
            total["errors"].append({"link_id": link.id, "engagement_id": link.engagement_id, "error": str(e)})
            continue
        ok_links += 1
        names |= set(st.pop("group_names"))
        for k in ("assets", "created", "updated", "removed"):
            total[k] += st[k]
    # Группы удаляем, только если все привязки ответили: иначе можно потерять группы недоступной.
    if links and ok_links == len(links):
        gone = [
            g for g in db.scalars(select(AssetGroup).where(AssetGroup.project_id == project_id)) if g.name not in names
        ]
        for g in gone:
            db.execute(delete(AssetGroupMember).where(AssetGroupMember.group_id == g.id))
            db.delete(g)
        total["groups_removed"] = len(gone)
    total["groups"] = len(names)
    db.flush()
    audit.record(
        db,
        actor,
        "assets.sync",
        object_type="project",
        object_id=project_id,
        project_id=project_id,
        ip=ip,
        result="ok" if not total["errors"] else "error",
        details={k: v for k, v in total.items() if k != "errors"} | {"errors": len(total["errors"])},
    )
    return total


def assets_by_address(db: Session, project_id: str) -> dict[str, Asset]:
    return {
        a.address: a
        for a in db.scalars(select(Asset).where(Asset.project_id == project_id).options(selectinload(Asset.groups)))
    }


def group_hosts(db: Session, project_id: str, names: Iterable[str]) -> set[str]:
    """Адреса активов, входящих хотя бы в одну из групп."""
    names = [n for n in names if n]
    if not names:
        return set()
    return set(
        db.scalars(
            select(Asset.address)
            .join(AssetGroupMember, AssetGroupMember.asset_id == Asset.id)
            .join(AssetGroup, AssetGroup.id == AssetGroupMember.group_id)
            .where(Asset.project_id == project_id, AssetGroup.name.in_(names))
        )
    )


def asset_brief(a: Asset | None) -> dict | None:
    if a is None:
        return None
    return {
        "id": a.id,
        "hostname": a.hostname,
        "owner": a.owner,
        "criticality": a.criticality,
        "tags": a.tags or [],
        "groups": [g.name for g in a.groups],
    }
