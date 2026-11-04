"""Проекты (= договор на работы). В режиме local — свой справочник с полями контракта платформы."""

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.common import paginate
from app.config import get_settings
from app.db import get_db
from app.deps import Principal, get_project, require
from app.models import Project
from app.rbac import Perm

router = APIRouter(tags=["projects"])


def project_out(pr: Project) -> dict:
    return {
        "id": pr.id,
        "name": pr.name,
        "client": pr.client,
        "contract_ref": pr.contract_ref,
        "period_from": pr.period_from,
        "period_to": pr.period_to,
        "status": pr.status,
        "platform_project_id": pr.platform_project_id,
        "created_at": pr.created_at,
    }


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str = Field(default="", max_length=200)
    contract_ref: str = Field(default="", max_length=200)
    period_from: date | None = None
    period_to: date | None = None


class ProjectPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    client: str | None = Field(default=None, max_length=200)
    contract_ref: str | None = Field(default=None, max_length=200)
    period_from: date | None = None
    period_to: date | None = None
    status: str | None = Field(default=None, pattern="^(active|archived)$")


def _local_only() -> None:
    if get_settings().auth_mode != "local":
        raise HTTPException(409, "В режиме платформы проекты создаются в «Платформе»")


@router.get("/projects")
def list_projects(
    response: Response,
    limit: int = 200,
    offset: int = 0,
    include_archived: bool = False,
    p: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
) -> list[dict]:
    stmt = select(Project).order_by(Project.name)
    if not include_archived:
        stmt = stmt.where(Project.status == "active")
    if "*" not in p.projects:
        stmt = stmt.where(Project.id.in_(p.projects))
    return [project_out(x) for x in paginate(db, stmt, response, limit, offset)]


@router.get("/projects/{project_id}")
def read_project(project_id: str, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)) -> dict:
    return project_out(get_project(db, project_id, p))


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectIn, p: Principal = Depends(require(Perm.PROJECTS_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    _local_only()
    pr = Project(**body.model_dump())
    db.add(pr)
    db.flush()
    audit.record(
        db,
        p.user,
        "project.create",
        object_type="project",
        object_id=pr.id,
        project_id=pr.id,
        ip=p.ip,
        details={"name": pr.name},
    )
    db.commit()
    return project_out(pr)


@router.patch("/projects/{project_id}")
def update_project(
    project_id: str,
    body: ProjectPatch,
    p: Principal = Depends(require(Perm.PROJECTS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    _local_only()
    pr = get_project(db, project_id, p)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(pr, k, v)
    audit.record(
        db,
        p.user,
        "project.update",
        object_type="project",
        object_id=pr.id,
        project_id=pr.id,
        ip=p.ip,
        details={k: str(v) for k, v in changes.items()},
    )
    db.commit()
    return project_out(pr)
