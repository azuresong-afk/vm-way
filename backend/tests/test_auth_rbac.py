from sqlalchemy import select

from app.models import AuditLog
from tests.conftest import PASSWORD, login


def test_login_and_me(client, users):
    h = login(client, "engineer")
    me = client.get("/me", headers=h).json()
    assert me["username"] == "engineer"
    assert "ticket_work" in me["permissions"] and "remediate_execute" in me["permissions"]
    assert "users_manage" not in me["permissions"]


def test_bad_password_is_audited(client, users, db):
    r = client.post("/auth/token", json={"username": "engineer", "password": "nope"})
    assert r.status_code == 401
    e = db.scalars(select(AuditLog).where(AuditLog.action == "auth.login")).all()
    assert [x.result for x in e] == ["denied"]
    assert "nope" not in str(e[0].details)


def test_no_token(client, users):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer x.y"}).status_code == 401


def test_admin_has_no_work_permissions(client, as_):
    me = client.get("/me", headers=as_("admin")).json()
    assert {"ticket_work", "verify", "import", "ticket_assign"}.isdisjoint(me["permissions"])


def test_viewer_cannot_manage_users_and_denial_audited(client, as_, db):
    assert client.get("/users", headers=as_("viewer")).status_code == 403
    denied = db.scalars(select(AuditLog).where(AuditLog.action == "access.denied")).all()
    assert denied and denied[0].username == "viewer"


def test_admin_creates_user_and_role_rules(client, as_):
    h = as_("admin")
    r = client.post(
        "/users", headers=h, json={"username": "new.eng", "password": "long-enough-pw", "roles": ["engineer"]}
    )
    assert r.status_code == 201
    assert client.get("/users", headers=h).headers["X-Total-Count"] == "5"
    bad = client.post(
        "/users", headers=h, json={"username": "x1", "password": "long-enough-pw", "roles": ["admin", "engineer"]}
    )
    assert bad.status_code == 422
    dup = client.post("/users", headers=h, json={"username": "new.eng", "password": "long-enough-pw"})
    assert dup.status_code == 409


def test_role_revocation_applies_immediately(client, as_, users):
    h = as_("manager")
    assert client.get("/audit", headers=h).status_code == 200
    client.patch(f"/users/{users['manager'].id}", headers=as_("admin"), json={"roles": ["viewer"]})
    assert client.get("/audit", headers=h).status_code == 403


def test_password_reset_invalidates_sessions(client, as_, users):
    h = as_("viewer")
    assert client.get("/me", headers=h).status_code == 200
    r = client.post(f"/users/{users['viewer'].id}/password", headers=as_("admin"), json={"password": "another-long-pw"})
    assert r.status_code == 200
    assert client.get("/me", headers=h).status_code == 401
    assert client.post("/auth/token", json={"username": "viewer", "password": PASSWORD}).status_code == 401


def test_secrets_never_in_audit(client, as_, db):
    client.post("/users", headers=as_("admin"), json={"username": "sec", "password": "super-secret-pw"})
    for e in db.scalars(select(AuditLog)):
        assert "super-secret-pw" not in str(e.details)


def test_projects(client, as_):
    r = client.post("/projects", headers=as_("admin"), json={"name": "Проект А", "client": "ООО «А»"})
    assert r.status_code == 201
    pid = r.json()["id"]
    assert client.post("/projects", headers=as_("manager"), json={"name": "x"}).status_code == 403
    assert client.get(f"/projects/{pid}", headers=as_("viewer")).json()["client"] == "ООО «А»"
    client.patch(f"/projects/{pid}", headers=as_("admin"), json={"status": "archived"})
    assert client.get("/projects", headers=as_("viewer")).json() == []


def test_audit_export(client, as_):
    r = client.get("/audit/export", headers=as_("admin"))
    assert r.status_code == 200 and "auth.login" in r.text
