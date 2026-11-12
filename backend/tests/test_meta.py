def test_manifest(client):
    m = client.get("/manifest").json()
    assert m["id"] == "vm" and m["base_path"] == "/vm/" and m["api_base"] == "/api/vm/"
    assert set(m["roles"]) == {"manager", "engineer", "viewer"}
    assert m["health_url"] == "/api/vm/health/ready"


def test_health(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_api_docs_only_in_demo(db_url, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import get_settings
    from app.main import create_app

    # Вне демо описание API закрыто: его отдавали бы без входа.
    with TestClient(create_app()) as c:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert c.get(path).status_code == 404, path
        assert c.get("/manifest").status_code == 200

    monkeypatch.setenv("VM_DEMO", "1")
    monkeypatch.setenv("VM_DEMO_PASSWORD", "demo-password-1")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as c:
            assert c.get("/docs").status_code == 200
            assert c.get("/openapi.json").json()["info"]["title"] == "Устранение API"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_env_example_lists_all_settings():
    """ТЗ: в .env.example перечислены все переменные (хотя бы закомментированной строкой)."""
    import re
    from pathlib import Path

    from app.config import Settings

    text = (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8")
    listed = set(re.findall(r"^#?\s*(VM_[A-Z0-9_]+)=", text, flags=re.M))
    missing = {f"VM_{name.upper()}" for name in Settings.model_fields} - listed
    assert not missing, f"нет в .env.example: {sorted(missing)}"
