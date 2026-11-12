"""Вход по логину и паролю (AUTH_MODE=local), выход и смена своего пароля."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import get_db
from app.deps import Principal, client_ip, session_principal
from app.models import RevokedToken, User
from app.rbac import ROLES
from app.security import hash_password, issue_token, verify_password
from app.services import login_guard

router = APIRouter(tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=200)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(min_length=10, max_length=200)

    @field_validator("new_password")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("пустой пароль")
        return v


def _throttle(db: Session, username: str, ip: str) -> None:
    wait = login_guard.retry_after(db, username, ip)
    if wait:
        raise HTTPException(429, login_guard.too_many(wait), headers={"Retry-After": str(wait)})


def _token_out(user: User) -> dict:
    token, ttl = issue_token(user.id, user.token_version)
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@router.post("/auth/token")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)) -> dict:
    if get_settings().auth_mode != "local":
        raise HTTPException(400, "Вход выполняется через «Платформу»")
    username, ip = body.username.strip(), client_ip(request)
    # Блокировка проверяется до пароля: пока она действует, подбирать пароль бесполезно.
    _throttle(db, username, ip)
    user = db.scalar(select(User).where(User.username == username))
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        login_guard.failure(user, username, ip)
        raise HTTPException(401, "Неверное имя пользователя или пароль")
    login_guard.clear(db, username, ip)
    audit.record(db, user, "auth.login", object_type="user", object_id=user.id, ip=ip)
    db.commit()
    return _token_out(user)


@router.post("/auth/logout")
def logout(p: Principal = Depends(session_principal), db: Session = Depends(get_db)) -> dict:
    # Токен отзывается: до конца своего срока он больше не принимается.
    now = int(time.time())
    db.execute(delete(RevokedToken).where(RevokedToken.expires_at < now))
    if p.jti:
        db.add(RevokedToken(jti=p.jti, user_id=p.user.id, expires_at=p.exp))
    audit.record(db, p.user, "auth.logout", object_type="user", object_id=p.user.id, ip=p.ip)
    db.commit()
    return {"ok": True}


def _can_change_password(u: User) -> bool:
    return get_settings().auth_mode == "local" and bool(u.password_hash)


@router.get("/me")
def me(p: Principal = Depends(session_principal)) -> dict:
    u = p.user
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "roles": u.roles,
        "role_labels": [ROLES[r]["label"] for r in u.roles if r in ROLES],
        "permissions": sorted(p.perms),
        "projects": p.projects,
        "must_change_password": u.must_change_password,
        "can_change_password": _can_change_password(u),
    }


@router.post("/me/password")
def change_password(
    body: PasswordChangeIn, p: Principal = Depends(session_principal), db: Session = Depends(get_db)
) -> dict:
    """Смена своего пароля. Все прежние сессии завершаются, текущая получает новый токен."""
    u = p.user
    if not _can_change_password(u):
        raise HTTPException(400, "Пароль этой учётной записи меняется не в «Устранении»")
    # Неверный текущий пароль считается так же, как неудачный вход: чужой токен не даёт подбирать пароль.
    _throttle(db, u.username, p.ip)
    if not verify_password(body.current_password, u.password_hash):
        login_guard.failure(u, u.username, p.ip, action="user.password_change")
        raise HTTPException(400, "Текущий пароль указан неверно")
    if body.new_password == body.current_password:
        raise HTTPException(422, "Новый пароль должен отличаться от текущего")
    u.password_hash = hash_password(body.new_password)
    u.token_version += 1  # все прежние сессии, включая эту, перестают действовать
    u.must_change_password = False
    login_guard.clear(db, u.username, p.ip)
    audit.record(db, u, "user.password_change", object_type="user", object_id=u.id, ip=p.ip)
    db.commit()
    return _token_out(u)
