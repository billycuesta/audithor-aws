from types import SimpleNamespace
import pytest
import audithor_app


@pytest.fixture
def client(monkeypatch):
    session = SimpleNamespace(_audithor_account_id="123456789012")
    monkeypatch.setattr(audithor_app.utils, "get_session", lambda data, **kwargs: (session, None))
    return audithor_app.app.test_client()


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
