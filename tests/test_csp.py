from conftest import make_client
import audithor_app


def test_dashboard_has_expected_csp_and_security_headers():
    response = make_client(audithor_app.app).get('/')
    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    assert csp == audithor_app.build_csp(audithor_app._bind_port)

    directives = {
        parts[0]: parts[1:]
        for directive in csp.split(";")
        if (parts := directive.strip().split())
    }
    assert "'unsafe-inline'" not in directives["script-src"]
    assert "'unsafe-eval'" not in directives["script-src"]
    assert directives["object-src"] == ["'none'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert f"http://127.0.0.1:{audithor_app._bind_port}" in directives["connect-src"]
    assert f"http://localhost:{audithor_app._bind_port}" in directives["connect-src"]
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_api_json_does_not_receive_csp():
    response = make_client(audithor_app.app).post('/api/run-sslscan', json={})
    assert response.is_json
    assert "Content-Security-Policy" not in response.headers


def test_bind_config_port_flows_into_csp():
    _, port = audithor_app.get_bind_config({"AUDITHOR_PORT": "6123"})
    assert "http://127.0.0.1:6123" in audithor_app.build_csp(port)
    assert "http://localhost:6123" in audithor_app.build_csp(port)
