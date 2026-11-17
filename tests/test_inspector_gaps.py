from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

from audithor.collectors import inspector
from tests.test_collection import Session, error, paginator_client


def test_inspector_status_exports_coverage_and_preserves_existing_keys():
    client = paginator_client([{"coveredResources": [{"resourceId": "i-1234567890", "accountId": "123456789012",
        "resourceType": "AWS_EC2_INSTANCE", "scanType": "NETWORK", "scanStatus": {"statusCode": "ACTIVE", "reason": ""},
        "lastScannedAt": datetime(2026, 1, 1, tzinfo=timezone.utc)}]}])
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012",
        "state": {"status": "ENABLED"}, "resourceState": {"ec2": {"status": "ENABLED"}}}]}
    result = inspector.collect_inspector_status(Session({"inspector2": client}))
    status = result["scan_status"][0]
    assert status["Region"] == "us-east-1"
    assert status["InspectorStatus"] == "ENABLED"
    assert status["ScanEC2"] == "ENABLED"
    assert status["Coverage"] == [{"resourceType": "AWS_EC2_INSTANCE", "resourceId": "i-1234567890",
        "scanType": "NETWORK", "scanStatus": "ACTIVE", "reason": "", "lastScannedAt": "2026-01-01T00:00:00+00:00"}]
    assert status["Enrichment"]["coverage"]["status"] == "complete"
    assert "findings" in result and "scan_status" in result and "findingsStatus" in result
    assert "coverage" not in result
    assert any(u.get("operation") == "list_coverage" and u.get("impact") == "enrichment" for u in result["_collection"]["units"])


def test_inspector_coverage_access_denied_is_enrichment_failure():
    client = paginator_client([])
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012", "state": {"status": "ENABLED"}}]}
    client.get_paginator.side_effect = error()
    result = inspector.collect_inspector_status(Session({"inspector2": client}))
    assert result["scan_status"][0]["Coverage"] == []
    assert result["scan_status"][0]["Enrichment"]["coverage"] == {"status": "failed", "reason": "permission_denied"}


def test_inspector_disabled_region_skips_coverage_enrichment():
    client = Mock()
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012", "state": {"status": "DISABLED"}}]}
    result = inspector.collect_inspector_status(Session({"inspector2": client}))
    status = result["scan_status"][0]
    client.get_paginator.assert_not_called()
    assert status["Enrichment"]["coverage"] == {"status": "skipped", "reason": "service_disabled"}


def test_inspector_list_coverage_uses_real_botocore_model():
    client = boto3.client("inspector2", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    client.batch_get_account_status = Mock(return_value={"accounts": [{"accountId": "123456789012", "state": {"status": "ENABLED"}}]})
    with Stubber(client) as stub:
        stub.add_response("list_coverage", {"coveredResources": [{"accountId": "123456789012", "resourceId": "i-1234567890",
            "resourceType": "AWS_EC2_INSTANCE", "scanType": "NETWORK", "scanStatus": {"statusCode": "ACTIVE", "reason": ""}}]},
            {"filterCriteria": {}})
        result = inspector.collect_inspector_status(Session({"inspector2": client}))
        stub.assert_no_pending_responses()
    assert result["scan_status"][0]["Coverage"][0]["scanStatus"] == "ACTIVE"
