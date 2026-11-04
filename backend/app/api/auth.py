"""Вход по логину и паролю (AUTH_MODE=local)."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import get_db
from app.deps import Principal, client_ip, current_principal
from app.models import User
from app.rbac import ROLES
from app.security import issue_token, verify_password

router = APIRouter(tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/auth/token")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)) -> dict:
    if get_settings().auth_mode != "local":
        raise HTTPException(400, "Вход выполняется через «Платформу»")
    user = db.scalar(select(User).where(User.username == body.username.strip()))
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        audit.record_separately(
            user, "auth.login", result="denied", ip=client_ip(request), details={"username": body.username[:64]}
        )
        raise HTTPException(401, "Неверное имя пользователя или пароль")
    token, ttl = issue_token(user.id, user.token_version)
    audit.record(db, user, "auth.login", object_type="user", object_id=user.id, ip=client_ip(request))
    db.commit()
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@router.post("/auth/logout")
def logout(p: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    audit.record(db, p.user, "auth.logout", object_type="user", object_id=p.user.id, ip=p.ip)
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(current_principal)) -> dict:
    u = p.user
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "roles": u.roles,
        "role_labels": [ROLES[r]["label"] for r in u.roles if r in ROLES],
        "permissions": sorted(p.perms),
        "projects": p.projects,
    }
