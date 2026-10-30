import pytest

from audithor_project import audithor_app
from conftest import make_client


def test_bind_config_defaults_overrides_and_invalid_port():
    assert audithor_app.get_bind_config({}) == ("127.0.0.1", 5001)
    assert audithor_app.get_bind_config({"AUDITHOR_HOST": "0.0.0.0", "AUDITHOR_PORT": "8123"}) == ("0.0.0.0", 8123)
    assert audithor_app.get_bind_config({"AUDITHOR_PORT": "70000"}) == ("127.0.0.1", 5001)


def test_cors_preflight_hosts_and_response_headers():
    client = make_client(audithor_app.app)
    for origin in ("http://127.0.0.1:5001", "http://localhost:5001"):
        response = client.options("/api/run-kms-audit", headers={"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type"})
        assert response.headers.get("Access-Control-Allow-Origin") == origin
    denied = client.options("/api/run-kms-audit", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_post_origin_content_type_and_body_limit(monkeypatch):
    client = make_client(audithor_app.app)
    assert client.post("/api/run-kms-audit", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/run-kms-audit", data="target=x", content_type="text/plain").status_code == 415
    monkeypatch.setitem(audithor_app.app.config, "MAX_CONTENT_LENGTH", 8)
    response = client.post("/api/run-kms-audit", data="x" * 32, content_type="application/json")
    assert response.status_code == 413 and response.is_json


def test_get_session_error_is_generic(monkeypatch):
    class FakeSession:
        def __init__(self, **kwargs): pass
        def client(self, *args, **kwargs): raise RuntimeError("SECRET-VALUE")
    monkeypatch.setattr(audithor_app.utils.boto3, "Session", FakeSession)
    _, error = audithor_app.utils.get_session({"access_key": "x", "secret_key": "y"})
    assert "SECRET-VALUE" not in error
    assert "could not be validated" in error


def test_error_hygiene_on_multiple_endpoints(monkeypatch):
    client = make_client(audithor_app.app)
    monkeypatch.setattr(audithor_app.utils, "get_session", lambda *args, **kwargs: (object(), None))
    endpoints = [
        ("/api/run-kms-audit", audithor_app.kms, "collect_kms_data"),
        ("/api/run-inventory-audit", audithor_app.inventory, "collect_inventory_summary"),
        ("/api/run-secrets-manager-audit", audithor_app.secrets_manager, "collect_secrets_manager_data"),
    ]
    for path, collector, method in endpoints:
        monkeypatch.setattr(collector, method, lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("SECRET-VALUE")))
        response = client.post(path, json={})
        assert response.status_code == 500
        assert "SECRET-VALUE" not in response.get_data(as_text=True)
