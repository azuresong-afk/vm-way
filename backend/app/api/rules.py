"""Правила назначения и команды (задача 2.2).

Правила — по проекту, по порядку; меняет руководитель (право `rules_manage`). Команды — общие для
всех проектов (как пользователи), их тоже ведёт руководитель. Применение правил по кнопке —
`POST /projects/{id}/rules/apply` (с `dry_run` — предпросмотр), право `ticket_assign`."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.api.common import not_found
from app.db import get_db, utcnow
from app.deps import Principal, get_project, require
from app.models import AssignmentRule, Team, User
from app.rbac import Perm
from app.services import rules as svc
from app.services.rules import RuleError

router = APIRouter(tags=["rules"])

MAX_RULES = 200


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_active: bool = True
    groups: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=100)
    owners: list[str] = Field(default_factory=list, max_length=100)
    os: list[str] = Field(default_factory=list, max_length=100)
    kinds: list[str] = Field(default_factory=list, max_length=20)
    host_match: Literal["all", "any"] = "all"
    assignee_id: int | None = None
    team_id: int | None = None


class RulePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = None
    groups: list[str] | None = Field(default=None, max_length=100)
    tags: list[str] | None = Field(default=None, max_length=100)
    owners: list[str] | None = Field(default=None, max_length=100)
    os: list[str] | None = Field(default=None, max_length=100)
    kinds: list[str] | None = Field(default=None, max_length=20)
    host_match: Literal["all", "any"] | None = None
    # Цель меняется парой: передайте одно из двух, второе станет пустым.
    assignee_id: int | None = None
    team_id: int | None = None


class OrderIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=MAX_RULES)


class ApplyIn(BaseModel):
    dry_run: bool = True
    ticket_ids: list[int] | None = Field(default=None, max_length=2000)


class TeamIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    member_ids: list[int] = Field(default_factory=list, max_length=500)


class TeamPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    member_ids: list[int] | None = Field(default=None, max_length=500)


def _snapshot(r: AssignmentRule) -> dict:
    return {
        "name": r.name,
        "position": r.position,
        "is_active": r.is_active,
        "groups": r.groups,
        "tags": r.tags,
        "owners": r.owners,
        "os": r.os,
        "kinds": r.kinds,
        "host_match": r.host_match,
        "assignee_id": r.assignee_id,
        "team_id": r.team_id,
    }


def _get_rule(db: Session, rule_id: int, p: Principal) -> AssignmentRule:
    r = db.get(AssignmentRule, rule_id)
    if r is None:
        raise not_found("Правило")
    get_project(db, r.project_id, p)
    return r


def _validate(db: Session, r: AssignmentRule) -> None:
    try:
        svc.validate(db, r)
    except RuleError as e:
        raise HTTPException(e.code, e.message)


def _out(db: Session, r: AssignmentRule) -> dict:
    db.refresh(r)
    return svc.rule_out(r)


@router.get("/projects/{project_id}/rules")
def list_rules(
    project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)
) -> list[dict]:
    get_project(db, project_id, p)
    return [svc.rule_out(r) for r in svc.project_rules(db, project_id)]


@router.post("/projects/{project_id}/rules", status_code=201)
def create_rule(
    project_id: str, body: RuleIn, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    get_project(db, project_id, p)
    count = db.scalar(select(func.count()).select_from(AssignmentRule).where(AssignmentRule.project_id == project_id))
    if count >= MAX_RULES:
        raise HTTPException(409, f"В проекте не больше {MAX_RULES} правил")
    last = db.scalar(select(func.max(AssignmentRule.position)).where(AssignmentRule.project_id == project_id))
    r = AssignmentRule(project_id=project_id, created_by=p.user.id, position=(last or 0) + 1, **body.model_dump())
    _validate(db, r)
    db.add(r)
    db.flush()
    audit.record(
        db,
        p.user,
        "rule.create",
        object_type="rule",
        object_id=r.id,
        project_id=project_id,
        ip=p.ip,
        details=_snapshot(r),
    )
    db.commit()
    return _out(db, r)


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: int, body: RulePatch, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    r = _get_rule(db, rule_id, p)
    before = _snapshot(r)
    changes = body.model_dump(exclude_unset=True)
    if "assignee_id" in changes or "team_id" in changes:
        r.assignee_id = changes.pop("assignee_id", None)
        r.team_id = changes.pop("team_id", None)
    for k, v in changes.items():
        if v is None:
            raise HTTPException(422, f"{k}: значение не может быть пустым")
        setattr(r, k, v)
    _validate(db, r)
    r.updated_at = utcnow()
    after = _snapshot(r)
    changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    if changed:
        audit.record(
            db,
            p.user,
            "rule.update",
            object_type="rule",
            object_id=r.id,
            project_id=r.project_id,
            ip=p.ip,
            details={"name": r.name, "changes": changed},
        )
    db.commit()
    return _out(db, r)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> None:
    r = _get_rule(db, rule_id, p)
    audit.record(
        db,
        p.user,
        "rule.delete",
        object_type="rule",
        object_id=r.id,
        project_id=r.project_id,
        ip=p.ip,
        details=_snapshot(r),
    )
    db.delete(r)
    db.commit()


@router.put("/projects/{project_id}/rules/order")
def reorder_rules(
    project_id: str, body: OrderIn, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> list[dict]:
    """Новый порядок правил: передаются все правила проекта по порядку."""
    get_project(db, project_id, p)
    rules = {r.id: r for r in svc.project_rules(db, project_id)}
    if sorted(body.ids) != sorted(rules) or len(set(body.ids)) != len(body.ids):
        raise HTTPException(422, "Передайте все правила проекта, каждое один раз")
    before = [r.id for r in svc.project_rules(db, project_id)]
    for i, rid in enumerate(body.ids, start=1):
        rules[rid].position = i
    if before != body.ids:
        audit.record(
            db,
            p.user,
            "rule.reorder",
            object_type="project",
            object_id=project_id,
            project_id=project_id,
            ip=p.ip,
            details={"from": before, "to": body.ids},
        )
    db.commit()
    return [svc.rule_out(r) for r in svc.project_rules(db, project_id)]


@router.post("/projects/{project_id}/rules/apply")
def apply_rules(
    project_id: str, body: ApplyIn, p: Principal = Depends(require(Perm.TICKET_ASSIGN)), db: Session = Depends(get_db)
) -> dict:
    """Применить правила к новым заявкам без исполнителя. По умолчанию — предпросмотр (dry_run)."""
    get_project(db, project_id, p)
    out = svc.apply(db, project_id, ticket_ids=body.ticket_ids, dry_run=body.dry_run, actor=p.user, ip=p.ip)
    if body.dry_run:
        db.rollback()
    else:
        db.commit()
    return out


# --- команды ---------------------------------------------------------------------------------


def _members(db: Session, ids: list[int]) -> list[User]:
    ids = list(dict.fromkeys(ids))
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids)))} if ids else {}
    missing = [i for i in ids if i not in users]
    if missing:
        raise HTTPException(422, f"Пользователи не найдены: {missing}")
    bad = [u.display_name or u.username for u in users.values() if not svc.can_work(u)]
    if bad:
        raise HTTPException(422, f"Не могут работать с заявками: {', '.join(bad)}")
    return [users[i] for i in ids]


def _team(db: Session, team_id: int) -> Team:
    t = db.scalar(select(Team).where(Team.id == team_id).options(selectinload(Team.members)))
    if t is None:
        raise not_found("Команда")
    return t


def _rules_count(db: Session) -> dict[int, int]:
    return dict(
        db.execute(
            select(AssignmentRule.team_id, func.count())
            .where(AssignmentRule.team_id.is_not(None))
            .group_by(AssignmentRule.team_id)
        ).all()
    )


def _name_free(db: Session, name: str, team_id: int | None = None) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(422, "Укажите название команды")
    other = db.scalar(select(Team).where(func.lower(Team.name) == name.lower()))
    if other is not None and other.id != team_id:
        raise HTTPException(409, "Команда с таким названием уже есть")
    return name


@router.get("/teams")
def list_teams(p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> list[dict]:
    counts = _rules_count(db)
    teams = db.scalars(select(Team).options(selectinload(Team.members)).order_by(Team.name))
    return [svc.team_out(t, counts.get(t.id, 0)) for t in teams]


@router.post("/teams", status_code=201)
def create_team(
    body: TeamIn, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    t = Team(name=_name_free(db, body.name))
    t.members = _members(db, body.member_ids)
    db.add(t)
    db.flush()
    audit.record(
        db,
        p.user,
        "team.create",
        object_type="team",
        object_id=t.id,
        ip=p.ip,
        details={"name": t.name, "members": [u.id for u in t.members]},
    )
    db.commit()
    return svc.team_out(_team(db, t.id))


@router.patch("/teams/{team_id}")
def update_team(
    team_id: int, body: TeamPatch, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    t = _team(db, team_id)
    before = {"name": t.name, "members": [u.id for u in t.members]}
    if body.name is not None:
        t.name = _name_free(db, body.name, t.id)
    if body.member_ids is not None:
        # Отключённые участники, уже стоящие в команде, могут остаться — правило их пропускает.
        keep = {u.id: u for u in t.members}
        new_ids = [i for i in dict.fromkeys(body.member_ids) if i not in keep]
        added = {u.id: u for u in _members(db, new_ids)}
        t.members = [keep.get(i) or added[i] for i in dict.fromkeys(body.member_ids)]
    after = {"name": t.name, "members": [u.id for u in t.members]}
    if before != after:
        audit.record(
            db,
            p.user,
            "team.update",
            object_type="team",
            object_id=t.id,
            ip=p.ip,
            details={"before": before, "after": after},
        )
    db.commit()
    return svc.team_out(_team(db, t.id), _rules_count(db).get(t.id, 0))


@router.delete("/teams/{team_id}", status_code=204)
def delete_team(
    team_id: int, p: Principal = Depends(require(Perm.RULES_MANAGE)), db: Session = Depends(get_db)
) -> None:
    t = _team(db, team_id)
    used = _rules_count(db).get(t.id, 0)
    if used:
        raise HTTPException(409, f"Команда используется в правилах назначения ({used}) — сначала измените их")
    audit.record(
        db,
        p.user,
        "team.delete",
        object_type="team",
        object_id=t.id,
        ip=p.ip,
        details={"name": t.name, "members": [u.id for u in t.members]},
    )
    db.delete(t)
    db.commit()
