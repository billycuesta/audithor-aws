from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError

from audithor.collectors import guardduty


class Session:
    def __init__(self, client):
        self.client_value = client
        self.ec2 = Mock()
        self.ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

    def get_available_regions(self, service, **kwargs):
        return ["us-east-1"]

    def client(self, service, **kwargs):
        return self.ec2 if service == "ec2" else self.client_value


def make_client():
    client = Mock()
    client.list_detectors.return_value = {"DetectorIds": ["detector"]}
    client.get_detector.return_value = {"Status": "ENABLED", "Features": [
        {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED", "AdditionalConfiguration": [
            {"Name": "DNS_LOGS", "Status": "ENABLED"}]},
        {"Name": "RUNTIME_MONITORING", "Status": "ENABLED"},
        {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
        {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
    ]}
    client.get_paginator.return_value.paginate.return_value = [{"FindingIds": ["finding"]}]
    client.get_findings.return_value = {"Findings": [{
        "Id": "finding", "Region": "us-east-1", "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "Severity": 7, "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-1"}},
        "UpdatedAt": datetime(2026, 1, 2, tzinfo=timezone.utc), "CreatedAt": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "Service": {"Archived": False, "Count": 3}, "Title": "Probe"}]}
    return client


def test_guardduty_features_and_finding_provenance():
    client = make_client()
    result = guardduty.collect_guardduty_data(Session(client))
    status = result["status"][0]
    assert status["Features"] == client.get_detector.return_value["Features"]
    finding = result["findings"][0]
    assert {key: finding[key] for key in ("Id", "Source", "Archived", "CreatedAt", "UpdatedAt", "Count")} == {
        "Id": "finding", "Source": "GuardDuty API", "Archived": False, "CreatedAt": "2026-01-01T00:00:00+00:00",
        "UpdatedAt": "2026-01-02T00:00:00+00:00", "Count": 3}
    assert finding["CollectedAt"].endswith("+00:00")
    assert {key for key in finding} >= {"SeverityScore", "SeverityLabel", "Region", "Type", "Resource", "LastSeen", "Title"}
    assert "results" not in result


def test_guardduty_feature_access_denied_is_enrichment_failure():
    client = make_client()
    client.get_detector.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetDetector")
    result = guardduty.collect_guardduty_data(Session(client))
    assert result["status"][0]["Enrichment"]["features"]["status"] == "failed"
    assert result["status"][0]["Enrichment"]["features"]["reason"] == "permission_denied"
    assert result["status"][0]["Status"] == "Error (ClientError)"


def test_guardduty_keeps_existing_keys():
    result = guardduty.collect_guardduty_data(Session(make_client()))
    assert set(result["status"][0]) >= {"Region", "Status", "S3 Logs", "Kubernetes Logs", "EC2 Malware Protection", "EKS Malware Protection"}
    assert set(result["findings"][0]) >= {"SeverityScore", "SeverityLabel", "Region", "Type", "Resource", "LastSeen", "Title"}


def test_guardduty_detector_model_stubber():
    client = boto3.client("guardduty", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(client) as stub:
        stub.add_response("list_detectors", {"DetectorIds": ["detector"]})
        stub.add_response("get_detector", {"Status": "ENABLED", "ServiceRole": "arn:aws:iam::123456789012:role/GuardDuty", "Features": [
            {"Name": "RUNTIME_MONITORING", "Status": "ENABLED", "AdditionalConfiguration": [
                {"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}]}
        ]}, {"DetectorId": "detector"})
        stub.add_response("list_findings", {"FindingIds": ["finding"]}, {
            "DetectorId": "detector", "FindingCriteria": {"Criterion": {"service.archived": {"Eq": ["false"]}}}})
        stub.add_response("get_findings", {"Findings": [{
            "AccountId": "123456789012", "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/detector/finding/finding",
            "CreatedAt": "2026-01-01T00:00:00Z", "Id": "finding", "Region": "us-east-1",
            "Resource": {"ResourceType": "Instance"}, "SchemaVersion": "2.0", "Severity": 7,
            "Type": "Recon:EC2/PortProbeUnprotectedPort", "UpdatedAt": "2026-01-02T00:00:00Z",
            "Service": {"Archived": True, "Count": 4}}]}, {"DetectorId": "detector", "FindingIds": ["finding"]})
        result = guardduty.collect_guardduty_data(Session(client))
        stub.assert_no_pending_responses()
    assert result["status"][0]["Features"][0]["AdditionalConfiguration"][0]["Name"] == "EKS_ADDON_MANAGEMENT"
    assert result["findings"][0]["Archived"] is True
    assert result["findings"][0]["Count"] == 4
