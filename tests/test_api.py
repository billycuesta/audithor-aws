from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
import audithor_app
from conftest import make_client
from audithor_project.collectors import playground


def test_sslscan_removal_contract(client, monkeypatch):
    assert client.post('/api/run-sslscan', json={}).status_code == 404
    assert not hasattr(playground, 'run_sslscan_on_targets')

    source_paths = (
        Path(audithor_app.__file__),
        Path(playground.__file__),
    )
    assert all("sslscan" not in path.read_text().lower() for path in source_paths)

    import shutil
    monkeypatch.setattr(shutil, "which", lambda command: (_ for _ in ()).throw(AssertionError(command)))
    assert client.post('/api/run-sslscan', json={}).status_code == 404


@pytest.fixture
def client(monkeypatch):
    session = SimpleNamespace(_audithor_account_id="123456789012")
    monkeypatch.setattr(audithor_app.utils, "get_session", lambda data, **kwargs: (session, None))
    return make_client(audithor_app.app)


def test_api_preserves_partial_and_scan_id(client, monkeypatch):
    def collect(session):
        return {"certificates": [], "_collection": {"status": "partial", "scanId": session._audithor_scan_id}}
    monkeypatch.setattr(audithor_app.acm, "collect_acm_data_web", collect)
    scan_id = "af5516eb-9b24-47e2-9cf0-bd76c297845c"
    response = client.post('/api/run-acm-audit', json={}, headers={"X-Scan-Id": scan_id})
    assert response.status_code == 200
    assert response.json["metadata"]["scanId"] == scan_id
    assert response.json["results"]["_collection"]["status"] == "partial"


def test_unexpected_error_is_sanitized(client, monkeypatch):
    monkeypatch.setattr(audithor_app.acm, "collect_acm_data_web", Mock(side_effect=RuntimeError("SECRET")))
    response = client.post('/api/run-acm-audit', json={})
    assert response.status_code == 500
    assert "SECRET" not in response.get_data(as_text=True)
    assert response.json["scanId"]


def test_collection_rejects_non_object_json_body(client, monkeypatch):
    get_session = Mock()
    monkeypatch.setattr(audithor_app.utils, "get_session", get_session)
    response = client.post('/api/run-acm-audit', json=["x"])
    assert response.status_code == 400
    assert response.is_json
    assert response.json == {"error": "Request body must be a JSON object", "scanId": response.json["scanId"]}
    get_session.assert_not_called()


def test_executive_summary_marks_incomplete_acm_not_assessed(client, monkeypatch):
    rule = next(rule for rule in audithor_app.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    monkeypatch.setattr(audithor_app, "RULES_TO_CHECK", [rule])
    response = client.post('/run_executive_summary', json={"acm": {
        "certificates": [], "_collection": {"status": "partial", "coverageKnown": True}
    }})
    assert response.status_code == 200
    assert response.json[0]["status"] == "NOT ASSESSED"


def test_executive_summary_violation_under_gap_is_red_flag_with_coverage(client, monkeypatch):
    rule = next(rule for rule in audithor_app.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    monkeypatch.setattr(audithor_app, "RULES_TO_CHECK", [rule])
    response = client.post('/run_executive_summary', json={"acm": {
        "certificates": [{"Status": "EXPIRED", "DomainName": "expired.example"}],
        "_collection": {"status": "partial", "coverageKnown": True}
    }})
    assert response.status_code == 200
    assert response.is_json
    assert response.json[0]["status"] == "🚩 RED FLAG"
    assert response.json[0]["coverage"] == [{
        "service": "acm", "status": "partial", "coverageKnown": True, "failedUnits": []
    }]


def test_executive_summary_complete_acm_coverage_returns_no_finding(client, monkeypatch):
    rule = next(rule for rule in audithor_app.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    monkeypatch.setattr(audithor_app, "RULES_TO_CHECK", [rule])
    response = client.post('/run_executive_summary', json={"acm": {
        "certificates": [], "_collection": {"status": "complete", "coverageKnown": True}
    }})
    assert response.status_code == 200
    assert response.json == []


def test_executive_summary_legacy_acm_data_is_unchanged(client, monkeypatch):
    rule = next(rule for rule in audithor_app.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    monkeypatch.setattr(audithor_app, "RULES_TO_CHECK", [rule])
    response = client.post('/run_executive_summary', json={"acm": {"certificates": []}})
    assert response.status_code == 200
    assert response.json == []


def test_session_connectivity_error_is_not_unauthorized(monkeypatch):
    from botocore.exceptions import EndpointConnectionError
    monkeypatch.setattr(audithor_app.utils, "get_session", Mock(side_effect=EndpointConnectionError(endpoint_url="https://example.invalid")))
    response = make_client(audithor_app.app).post('/api/run-acm-audit', json={})
    assert response.status_code == 503
    assert response.json["category"] == "connectivity_error"
