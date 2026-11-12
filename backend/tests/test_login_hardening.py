"""Вход (задача Г ревью): защита от перебора, смена своего пароля, отзыв токена при выходе."""

import time

import pytest
from sqlalchemy import select, update

from app.config import get_settings
from app.models import AuditLog, LoginFailure, RevokedToken, User
from tests.conftest import PASSWORD, first_login, login

NEW = "my-own-long-password"


def _try(client, username, password="wrong-password", ip=None):
    headers = {"X-Real-IP": ip} if ip else {}
    return client.post("/auth/token", json={"username": username, "password": password}, headers=headers)


def _actions(db, action):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)).all()


# --- защита от перебора ---


def test_lockout_after_repeated_failures(client, users, db):
    limit = get_settings().login_max_failures
    for _ in range(limit):
        assert _try(client, "engineer").status_code == 401
    r = _try(client, "engineer", PASSWORD)  # верный пароль во время блокировки тоже не проходит
    assert r.status_code == 429
    assert 0 < int(r.headers["Retry-After"]) <= get_settings().login_window_minutes * 60
    assert "Повторите через" in r.json()["detail"]
    # Блокировка записана в аудит один раз, заблокированные попытки журнал не раздувают.
    assert len(_actions(db, "auth.lockout")) == 1
    assert len(_actions(db, "auth.login")) == limit
    _try(client, "engineer")
    assert len(_actions(db, "auth.login")) == limit
    assert db.scalar(select(LoginFailure).where(LoginFailure.username == "engineer")) is not None


def test_lockout_is_per_account_and_address(client, users):
    for _ in range(get_settings().login_max_failures):
        _try(client, "engineer", ip="10.0.0.1")
    assert _try(client, "engineer", PASSWORD, ip="10.0.0.1").status_code == 429
    # Тот же пользователь с другого адреса и другой пользователь с того же адреса входят.
    assert _try(client, "engineer", PASSWORD, ip="10.0.0.2").status_code == 200
    assert _try(client, "manager", PASSWORD, ip="10.0.0.1").status_code == 200


def test_lockout_expires_with_window(client, users, db):
    for _ in range(get_settings().login_max_failures):
        _try(client, "engineer")
    assert _try(client, "engineer", PASSWORD).status_code == 429
    old = int(time.time()) - get_settings().login_window_minutes * 60 - 1
    db.execute(update(LoginFailure).values(at=old))
    db.commit()
    assert _try(client, "engineer", PASSWORD).status_code == 200


def test_success_resets_pair_counter(client, users):
    limit = get_settings().login_max_failures
    for _ in range(limit - 1):
        _try(client, "engineer")
    assert _try(client, "engineer", PASSWORD).status_code == 200
    for _ in range(limit - 1):
        assert _try(client, "engineer").status_code == 401
    assert _try(client, "engineer", PASSWORD).status_code == 200


def test_unknown_usernames_are_throttled_too(client, users):
    for _ in range(get_settings().login_max_failures):
        assert _try(client, "nobody").status_code == 401
    assert _try(client, "nobody").status_code == 429
    assert _try(client, "NoBody ").status_code == 429  # регистр и пробелы не обходят счётчик


def test_address_limit_stops_password_spraying(client, users, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_max_failures_ip", 6)
    for i in range(6):
        assert _try(client, f"user{i}", ip="10.0.0.9").status_code == 401
    assert _try(client, "engineer", PASSWORD, ip="10.0.0.9").status_code == 429
    assert _try(client, "engineer", PASSWORD, ip="10.0.0.10").status_code == 200


def test_account_limit_covers_many_addresses(client, users, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_max_failures_account", 6)
    for i in range(6):
        assert _try(client, "engineer", ip=f"10.0.1.{i}").status_code == 401
    assert _try(client, "engineer", PASSWORD, ip="10.0.2.1").status_code == 429


# --- отзыв токена при выходе ---


def test_logout_revokes_only_this_token(client, users, db):
    h1, h2 = login(client, "engineer"), login(client, "engineer")
    assert client.post("/auth/logout", headers=h1).status_code == 200
    assert client.get("/me", headers=h1).status_code == 401
    assert client.get("/projects", headers=h1).status_code == 401
    assert client.post("/auth/logout", headers=h1).status_code == 401
    assert client.get("/me", headers=h2).status_code == 200  # другая сессия того же пользователя жива
    assert len(db.scalars(select(RevokedToken)).all()) == 1


def test_logout_prunes_expired_revocations(client, users, db):
    db.add(RevokedToken(jti="old", user_id=users["engineer"].id, expires_at=int(time.time()) - 10))
    db.commit()
    client.post("/auth/logout", headers=login(client, "engineer"))
    assert [t.jti for t in db.scalars(select(RevokedToken))] != ["old"]
    assert db.get(RevokedToken, "old") is None


# --- смена своего пароля ---


def test_change_own_password(client, users, db):
    h_old, h_other = login(client, "engineer"), login(client, "engineer")
    r = client.post("/me/password", headers=h_old, json={"current_password": PASSWORD, "new_password": NEW})
    assert r.status_code == 200, r.text
    h_new = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/me", headers=h_new).status_code == 200
    # Все прежние сессии завершены, старый пароль не подходит, новый подходит.
    assert client.get("/me", headers=h_old).status_code == 401
    assert client.get("/me", headers=h_other).status_code == 401
    assert _try(client, "engineer", PASSWORD).status_code == 401
    assert _try(client, "engineer", NEW).status_code == 200
    entries = _actions(db, "user.password_change")
    assert [e.result for e in entries] == ["ok"] and entries[0].username == "engineer"
    assert NEW not in str(entries[0].details) and PASSWORD not in str(entries[0].details)


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"current_password": "wrong-password", "new_password": NEW}, 400),
        ({"current_password": PASSWORD, "new_password": PASSWORD}, 422),
        ({"current_password": PASSWORD, "new_password": "short"}, 422),
        ({"current_password": PASSWORD, "new_password": " " * 12}, 422),
    ],
)
def test_change_password_rejections(client, as_, body, status):
    h = as_("engineer")
    assert client.post("/me/password", headers=h, json=body).status_code == status
    assert client.get("/me", headers=h).status_code == 200  # сессия не пострадала
    assert _try(client, "engineer", PASSWORD).status_code == 200


def test_change_password_needs_session(client, users):
    r = client.post("/me/password", json={"current_password": PASSWORD, "new_password": NEW})
    assert r.status_code == 401


def test_wrong_current_password_is_throttled(client, as_, db):
    h = as_("engineer")
    body = {"current_password": "wrong-password", "new_password": NEW}
    for _ in range(get_settings().login_max_failures):
        assert client.post("/me/password", headers=h, json=body).status_code == 400
    r = client.post("/me/password", headers=h, json={"current_password": PASSWORD, "new_password": NEW})
    assert r.status_code == 429
    assert all(e.result == "denied" for e in _actions(db, "user.password_change"))


# --- обязательная смена пароля, выданного администратором ---


def test_new_user_must_change_password(client, as_, db):
    admin = as_("admin")
    r = client.post(
        "/users", headers=admin, json={"username": "new.eng", "password": "issued-by-admin", "roles": ["engineer"]}
    )
    assert r.status_code == 201 and r.json()["must_change_password"] is True
    h = login_as(client, "new.eng", "issued-by-admin")
    me = client.get("/me", headers=h).json()
    assert me["must_change_password"] is True and me["can_change_password"] is True
    # До смены пароля доступны только /me, смена пароля и выход.
    assert client.get("/projects", headers=h).status_code == 403
    assert client.get("/roles", headers=h).status_code == 403
    r = client.post("/me/password", headers=h, json={"current_password": "issued-by-admin", "new_password": NEW})
    assert r.status_code == 200
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/me", headers=h).json()["must_change_password"] is False
    assert client.get("/projects", headers=h).status_code == 200
    assert db.scalar(select(User).where(User.username == "new.eng")).must_change_password is False


def test_admin_reset_forces_change_but_not_for_self(client, as_, users, db):
    admin = as_("admin")
    client.post(f"/users/{users['viewer'].id}/password", headers=admin, json={"password": "issued-by-admin"})
    h = login_as(client, "viewer", "issued-by-admin")
    assert client.get("/projects", headers=h).status_code == 403
    assert client.post("/auth/logout", headers=h).status_code == 200  # выйти можно и без смены
    # Администратор, сбросивший пароль самому себе, знает его сам — смена не требуется.
    client.post(f"/users/{users['admin'].id}/password", headers=admin, json={"password": "admins-new-password"})
    h = login_as(client, "admin", "admins-new-password")
    assert client.get("/users", headers=h).status_code == 200


def test_first_login_helper(client, as_):
    client.post("/users", headers=as_("admin"), json={"username": "x.y", "password": "issued-by-admin"})
    assert client.get("/me", headers=first_login(client, "x.y", "issued-by-admin")).status_code == 200


def login_as(client, username, password):
    r = client.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
