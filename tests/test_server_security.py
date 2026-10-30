import threading
import time

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
        response = client.options("/api/run-sslscan", headers={"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type"})
        assert response.headers.get("Access-Control-Allow-Origin") == origin
    denied = client.options("/api/run-sslscan", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_post_origin_content_type_and_body_limit(monkeypatch):
    client = make_client(audithor_app.app)
    assert client.post("/api/run-sslscan", json={"target": "example.com"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/run-sslscan", json={"target": "invalid"}).status_code == 200
    assert client.post("/api/run-sslscan", data="target=x", content_type="text/plain").status_code == 415
    monkeypatch.setitem(audithor_app.app.config, "MAX_CONTENT_LENGTH", 8)
    response = client.post("/api/run-sslscan", data="x" * 32, content_type="application/json")
    assert response.status_code == 413 and response.is_json


def test_sslscan_rejects_too_many_targets_and_invalid_target(monkeypatch):
    client = make_client(audithor_app.app)
    response = client.post("/api/run-sslscan", json={"target": ",".join(f"host{i}.example" for i in range(11))})
    assert response.status_code == 400
    assert "10 targets" in response.json["error"]
    calls = []
    monkeypatch.setattr(audithor_app.playground.shutil, "which", lambda _: "/usr/bin/sslscan")
    monkeypatch.setattr(audithor_app.playground.subprocess, "run", lambda argv, **kwargs: calls.append(argv) or type("Result", (), {"stdout": "ok", "stderr": ""})())
    results = audithor_app.playground.run_sslscan_on_targets("example.com, bad_target")
    assert [call[-1] for call in calls] == ["example.com"]
    assert len(results) == 2
    invalid = next(item for item in results if item["target"] == "bad_target")
    assert "error" in invalid


def test_sslscan_deduplicates_and_limits_concurrency(monkeypatch):
    active = maximum = 0
    lock = threading.Lock()
    def slow_run(argv, **kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return type("Result", (), {"stdout": "ok", "stderr": ""})()
    monkeypatch.setattr(audithor_app.playground.shutil, "which", lambda _: "/usr/bin/sslscan")
    monkeypatch.setattr(audithor_app.playground.subprocess, "run", slow_run)
    results = audithor_app.playground.run_sslscan_on_targets("a.example, a.example, b.example, c.example, d.example, e.example, f.example")
    assert len(results) == 6
    assert maximum <= 4


def test_sslscan_deadline_returns_timeout_entries(monkeypatch):
    from concurrent.futures import TimeoutError as FutureTimeoutError

    monkeypatch.setattr(audithor_app.playground.shutil, "which", lambda _: "/usr/bin/sslscan")
    monkeypatch.setattr(audithor_app.playground.subprocess, "run", lambda *args, **kwargs: time.sleep(0.15))
    monkeypatch.setattr(audithor_app.playground, "TimeoutError", type("LegacyBuiltinTimeout", (Exception,), {}), raising=False)
    monkeypatch.setattr(audithor_app.playground, "as_completed", lambda *args, **kwargs: (_ for _ in ()).throw(FutureTimeoutError()))
    results = audithor_app.playground.run_sslscan_on_targets("a.example,b.example", deadline_seconds=0.02)
    assert len(results) == 2
    assert all("error" in item and "deadline" in item["error"].lower() for item in results)


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
