"""Зависимости FastAPI: текущий пользователь и проверка прав."""

from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.models import Project, RevokedToken, User
from app.rbac import Perm, perms_for
from app.security import read_token


@dataclass
class Principal:
    user: User
    perms: set[str]
    ip: str = ""
    projects: list[str] = field(default_factory=lambda: ["*"])
    # Идентификатор и срок токена текущей сессии — для отзыва при выходе.
    jti: str = ""
    exp: int = 0

    def can(self, perm: Perm | str) -> bool:
        return str(perm) in self.perms


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return fwd or (request.client.host if request.client else "")


def session_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    """Пользователь по токену — без проверки «нужно сменить пароль». Только для входа, выхода,
    /me и смены своего пароля; всё остальное зависит от `current_principal`."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Требуется вход")
    payload = read_token(header[7:].strip())
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия истекла, войдите снова")
    # Пользователь и его роли читаются из БД на каждый запрос: отзыв роли действует сразу.
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active or user.token_version != payload.get("ver"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия недействительна")
    jti = str(payload.get("jti") or "")
    if jti and db.get(RevokedToken, jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия завершена, войдите снова")
    return Principal(
        user=user,
        perms=perms_for(user.roles or [], user.extra_perms or []),
        ip=client_ip(request),
        jti=jti,
        exp=int(payload.get("exp", 0)),
    )


def current_principal(p: Principal = Depends(session_principal)) -> Principal:
    if p.user.must_change_password:
        # Пароль выдан администратором: пока пользователь не задал свой, работать под ним нельзя.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Сначала смените пароль, выданный администратором")
    return p


def require(perm: Perm) -> Callable[..., Principal]:
    def dep(request: Request, p: Principal = Depends(current_principal)) -> Principal:
        if not p.can(perm):
            audit.record_separately(
                p.user,
                "access.denied",
                result="denied",
                ip=p.ip,
                details={"perm": str(perm), "path": request.url.path, "method": request.method},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Недостаточно прав")
        return p

    return dep


def get_project(db: Session, project_id: str, p: Principal) -> Project:
    project = db.get(Project, project_id)
    if not project or ("*" not in p.projects and project_id not in p.projects):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    return project
