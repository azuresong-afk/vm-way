def test_manifest(client):
    m = client.get("/manifest").json()
    assert m["id"] == "vm" and m["base_path"] == "/vm/" and m["api_base"] == "/api/vm/"
    assert set(m["roles"]) == {"manager", "engineer", "viewer"}
    assert m["health_url"] == "/api/vm/health/ready"


def test_health(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ok"}
