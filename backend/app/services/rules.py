"""Правила назначения (задача 2.2).

Правило — условия и цель. Условия:
- группа активов, тег, владелец актива — свойства **хостов** заявки (берутся из активов «Сканера»);
- ОС и вид — свойства самой заявки.
Внутри одного условия значения через «или», между условиями — «и», пустое условие — любое значение.

Выбор: условия по хостам по умолчанию должны выполняться для **всех** неподтверждённых хостов
заявки (`host_match = all`): заявка «Обновить openssh на Debian 12» обычно охватывает хосты разных
групп и владельцев, и правило «группа DMZ → команда веб-сервисов» не должно забирать её из-за одного
хоста. Для правила можно выбрать «хотя бы один хост» (`any`). Хост без актива в «Сканере» условиям
по хостам не удовлетворяет.

Цель — исполнитель или команда. Команда распределяет по загрузке: заявка достаётся участнику с
наименьшим числом открытых заявок проекта (при равенстве — тому, кто раньше добавлен в систему).
Отключённые пользователи и пользователи без права работать с заявками пропускаются. Если у правила
некому назначить, проверяется следующее правило.

Правила проверяются по порядку, срабатывает первое подходящее. Применяются только к новым
заявкам без исполнителя: автоматически — к заявкам, созданным импортом, и по кнопке «Применить»
— ко всем таким заявкам проекта (с предпросмотром). Назначение пишется в историю заявки, журнал
(`ticket.assign` от имени «система», `via=rule`) и outbox, как ручное.
"""

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.models import Asset, AssignmentRule, Team, Ticket, User
from app.rbac import Perm, perms_for
from app.services import assets as assets_svc
from app.services.workflow import CLOSED_STATUSES, assign

HOST_MATCH = {"all": "все хосты заявки", "any": "хотя бы один хост"}
MAX_VALUES = 100


class RuleError(Exception):
    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.message = message
        self.code = code


def _clean_list(values: list[str] | None, n: int, *, lower: bool = False) -> list[str]:
    out: list[str] = []
    for v in values or []:
        v = str(v).strip()[:n]
        if lower:
            v = v.lower()
        if v and v not in out:
            out.append(v)
    if len(out) > MAX_VALUES:
        raise RuleError(f"Не больше {MAX_VALUES} значений в условии")
    return out


def can_work(u: User | None) -> bool:
    return bool(u and u.is_active and Perm.TICKET_WORK in perms_for(u.roles or [], u.extra_perms or []))


def validate(db: Session, r: AssignmentRule) -> None:
    from app.services.mirror import KIND_LABELS

    r.name = (r.name or "").strip()[:200]
    if not r.name:
        raise RuleError("Укажите название правила")
    r.groups = _clean_list(r.groups, 128)
    r.tags = _clean_list(r.tags, 64, lower=True)
    r.owners = _clean_list(r.owners, 256)
    r.os = _clean_list(r.os, 120)
    r.kinds = _clean_list(r.kinds, 32)
    bad = [k for k in r.kinds if k not in KIND_LABELS]
    if bad:
        raise RuleError(f"Неизвестный вид заявки: {', '.join(bad)}")
    if r.host_match not in HOST_MATCH:
        raise RuleError("Совпадение по хостам: all или any")
    if (r.assignee_id is None) == (r.team_id is None):
        raise RuleError("Выберите исполнителя или команду")
    if r.assignee_id is not None and not can_work(db.get(User, r.assignee_id)):
        raise RuleError("Исполнитель не найден, отключён или не может работать с заявками")
    if r.team_id is not None and db.get(Team, r.team_id) is None:
        raise RuleError("Команда не найдена")


def project_rules(db: Session, project_id: str, *, active_only: bool = False) -> list[AssignmentRule]:
    stmt = (
        select(AssignmentRule)
        .where(AssignmentRule.project_id == project_id)
        .options(selectinload(AssignmentRule.assignee), selectinload(AssignmentRule.team).selectinload(Team.members))
    )
    if active_only:
        stmt = stmt.where(AssignmentRule.is_active.is_(True))
    return list(db.scalars(stmt.order_by(AssignmentRule.position, AssignmentRule.id)))


def has_host_conditions(r: AssignmentRule) -> bool:
    return bool(r.groups or r.tags or r.owners)


def _host_ok(r: AssignmentRule, a: Asset | None) -> bool:
    if a is None:
        return False
    if r.groups and not {g.name for g in a.groups} & set(r.groups):
        return False
    if r.tags and not set(a.tags or []) & set(r.tags):
        return False
    return not (r.owners and a.owner not in r.owners)


def matches(r: AssignmentRule, t: Ticket, assets: dict[str, Asset]) -> bool:
    if r.kinds and t.kind not in r.kinds:
        return False
    if r.os and t.os not in r.os:
        return False
    if not has_host_conditions(r):
        return True
    hosts = [h.host for h in t.hosts if h.status != "confirmed"] or [h.host for h in t.hosts]
    if not hosts:
        return False
    ok = [_host_ok(r, assets.get(h)) for h in hosts]
    return all(ok) if r.host_match == "all" else any(ok)


class Load:
    """Загрузка исполнителей: открытые заявки проекта. Обновляется по ходу применения правил."""

    def __init__(self, db: Session, project_id: str):
        self.counts: dict[int, int] = dict(
            db.execute(
                select(Ticket.assignee_id, func.count())
                .where(
                    Ticket.project_id == project_id,
                    Ticket.assignee_id.is_not(None),
                    Ticket.status.not_in(CLOSED_STATUSES),
                )
                .group_by(Ticket.assignee_id)
            ).all()
        )

    def get(self, user_id: int) -> int:
        return self.counts.get(user_id, 0)

    def add(self, user_id: int) -> None:
        self.counts[user_id] = self.get(user_id) + 1


def pick(r: AssignmentRule, load: Load) -> User | None:
    """Кому правило назначит заявку прямо сейчас (None — некому)."""
    if r.assignee_id is not None:
        return r.assignee if can_work(r.assignee) else None
    if r.team is None:
        return None
    members = [u for u in r.team.members if can_work(u)]
    if not members:
        return None
    return min(members, key=lambda u: (load.get(u.id), u.id))


@dataclass
class Decision:
    ticket: Ticket
    rule: AssignmentRule | None
    user: User | None
    note: str = ""

    def out(self) -> dict:
        t = self.ticket
        return {
            "ticket_id": t.id,
            "title": t.title,
            "severity": t.effective_severity,
            "kind": t.kind,
            "os": t.os,
            "rule": {"id": self.rule.id, "name": self.rule.name} if self.rule else None,
            "assignee": (
                {"id": self.user.id, "display_name": self.user.display_name or self.user.username}
                if self.user
                else None
            ),
            "note": self.note,
        }


def candidates(db: Session, project_id: str, ticket_ids: list[int] | None = None) -> list[Ticket]:
    """Заявки, к которым применяются правила: «Новая» без исполнителя."""
    stmt = (
        select(Ticket)
        .where(Ticket.project_id == project_id, Ticket.status == "new", Ticket.assignee_id.is_(None))
        .options(selectinload(Ticket.hosts))
    )
    if ticket_ids is not None:
        if not ticket_ids:
            return []
        stmt = stmt.where(Ticket.id.in_(ticket_ids))
    return list(db.scalars(stmt.order_by(Ticket.priority_rank.is_(None), Ticket.priority_rank, Ticket.id)))


def decide(db: Session, project_id: str, tickets: list[Ticket], *, load: Load | None = None) -> list[Decision]:
    """Какое правило сработает для каждой заявки и кому она достанется. Ничего не меняет,
    кроме счётчиков загрузки `load` (чтобы команда распределяла по очереди)."""
    rules = project_rules(db, project_id, active_only=True)
    if not rules or not tickets:
        return [Decision(t, None, None, "нет включённых правил" if not rules else "") for t in tickets]
    assets = assets_svc.assets_by_address(db, project_id)
    load = load or Load(db, project_id)
    out = []
    for t in tickets:
        decision = Decision(t, None, None, "ни одно правило не подошло")
        skipped: list[str] = []
        for r in rules:
            if not matches(r, t, assets):
                continue
            u = pick(r, load)
            if u is None:
                skipped.append(r.name)
                continue
            load.add(u.id)
            decision = Decision(t, r, u)
            break
        if decision.rule is None and skipped:
            decision.note = f"подошло, но некому назначить: {', '.join(skipped)}"
        out.append(decision)
    return out


def _rule_ref(r: AssignmentRule) -> dict:
    return {"rule_id": r.id, "rule_name": r.name, **({"team": r.team.name} if r.team else {})}


def apply(
    db: Session,
    project_id: str,
    *,
    ticket_ids: list[int] | None = None,
    dry_run: bool = False,
    actor: User | None = None,
    ip: str = "",
) -> dict:
    """Применяет правила к новым заявкам без исполнителя. dry_run — только предпросмотр.

    ticket_ids None — все такие заявки проекта; список — только эти (импорт передаёт созданные)."""
    tickets = candidates(db, project_id, ticket_ids)
    decisions = decide(db, project_id, tickets)
    assigned = 0
    if not dry_run:
        for d in decisions:
            if d.rule is None:
                continue
            assign(
                db,
                d.ticket,
                None,
                d.user.id,
                via="rule",
                extra={
                    "rule_id": d.rule.id,
                    "rule_name": d.rule.name,
                    **({"team": d.rule.team.name} if d.rule.team else {}),
                },
            )
            assigned += 1
        if assigned or actor is not None:
            audit.record(
                db,
                actor,
                "rules.apply",
                object_type="project",
                object_id=project_id,
                project_id=project_id,
                ip=ip,
                details={"tickets": len(tickets), "assigned": assigned, "auto": actor is None},
            )
        db.flush()
    return {
        "dry_run": dry_run,
        "tickets": len(tickets),
        "assigned": assigned if not dry_run else sum(1 for d in decisions if d.rule),
        "items": [d.out() for d in decisions],
    }


def rule_out(r: AssignmentRule) -> dict:
    return {
        "id": r.id,
        "project_id": r.project_id,
        "position": r.position,
        "name": r.name,
        "is_active": r.is_active,
        "groups": r.groups or [],
        "tags": r.tags or [],
        "owners": r.owners or [],
        "os": r.os or [],
        "kinds": r.kinds or [],
        "host_match": r.host_match,
        "assignee": (
            {
                "id": r.assignee.id,
                "display_name": r.assignee.display_name or r.assignee.username,
                "available": can_work(r.assignee),
            }
            if r.assignee
            else None
        ),
        "team": (
            {
                "id": r.team.id,
                "name": r.team.name,
                "members": sum(1 for u in r.team.members if can_work(u)),
            }
            if r.team
            else None
        ),
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }


def team_out(t: Team, rules_count: int = 0) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "members": [
            {
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
                "available": can_work(u),
            }
            for u in t.members
        ],
        "rules": rules_count,
        "created_at": t.created_at,
    }
