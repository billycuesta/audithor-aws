import json
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber, ANY

from audithor.collectors import cloudtrail


class Session:
    def __init__(self, clients):
        self.clients = clients

    def client(self, service, **kwargs):
        return self.clients[service]


def test_trail_enrichment_events_and_existing_keys(monkeypatch):
    ct = Mock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "audit", "TrailARN": "arn:trail", "HomeRegion": "us-east-1", "S3BucketName": "logs"}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    ct.get_event_selectors.return_value = {"EventSelectors": [{"ReadWriteType": "All", "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:bucket/"]}]}], "AdvancedEventSelectors": [{"Name": "adv"}]}
    ct.get_insight_selectors.return_value = {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}
    ct.get_paginator.return_value.paginate.return_value = [{"Events": [{"EventName": "ConsoleLogin", "EventTime": "2025-01-01", "CloudTrailEvent": json.dumps({"errorCode": "Denied", "errorMessage": "<img src=x onerror=alert(1)>", "userIdentity": {"sessionContext": {"attributes": {"mfaAuthenticated": "true"}}}})}]}]
    s3 = Mock()
    s3.get_bucket_lifecycle_configuration.return_value = {"Rules": [{"Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 90}}]}
    monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, trails: [])
    result = cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": s3}))
    trail, event = result["trails"][0], result["events"][0]
    assert trail["Name"] == "audit" and trail["TrailARN"] == "arn:trail"
    assert trail["EventSelectors"][0]["ReadWriteType"] == "All"
    assert trail["AdvancedEventSelectors"][0]["Name"] == "adv"
    assert trail["InsightSelectors"][0]["InsightType"] == "ApiCallRateInsight"
    assert trail["LogBucketLifecycle"]["RetentionDays"] == 90
    assert set(trail["Enrichment"]) == {"selectors", "insights", "lifecycle"}
    assert event["ErrorCode"] == "Denied"
    assert event["ErrorMessage"] == "<img src=x onerror=alert(1)>"
    assert event["MFAUsed"] is True


def test_selector_failure_is_classified(monkeypatch):
    ct = Mock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "audit", "TrailARN": "arn:trail", "HomeRegion": "us-east-1"}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    ct.get_event_selectors.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetEventSelectors")
    ct.get_insight_selectors.return_value = {"InsightSelectors": []}
    ct.get_paginator.return_value.paginate.return_value = []
    monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, trails: [])
    result = cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": Mock()}))
    assert result["trails"][0]["Enrichment"]["selectors"] == {"status": "failed", "reason": "permission_denied"}


def test_lifecycle_retention_matches_cloudtrail_log_roots(monkeypatch):
    rules = [
        {"Status": "Enabled", "Filter": {"Prefix": "AWSLogs/"}, "Expiration": {"Days": 90}},
        {"Status": "Enabled", "Filter": {"Prefix": "ct/"}, "Expiration": {"Days": 60}},
        {"Status": "Enabled", "Filter": {"Prefix": "ct"}, "Expiration": {"Days": 20}},
        {"Status": "Enabled", "Filter": {"Prefix": "audit/"}, "Expiration": {"Days": 4}},
        {"Status": "Enabled", "Filter": {"And": {"Prefix": "ct-other/AWSLogs/", "Tags": [{"Key": "x", "Value": "y"}]}}, "Expiration": {"Days": 5}},
        {"Status": "Enabled", "Filter": {"And": {"Prefix": "ct-other/"}}, "Expiration": {"Days": 45}},
        {"Status": "Enabled", "Prefix": "ct-other/AWSLogs/", "Expiration": {"Days": 30}},
        {"Status": "Enabled", "Filter": {"Tag": {"Key": "x", "Value": "y"}}, "Expiration": {"Days": 1}},
        {"Status": "Disabled", "Filter": {"Prefix": "ct-other/"}, "Expiration": {"Days": 2}},
    ]
    trails = [
        {"Name": "no-prefix", "TrailARN": "arn:no-prefix", "HomeRegion": "us-east-1", "S3BucketName": "bucket"},
        {"Name": "ct-prefix", "TrailARN": "arn:ct", "HomeRegion": "us-east-1", "S3BucketName": "bucket", "S3KeyPrefix": "ct"},
        {"Name": "ct-other", "TrailARN": "arn:ct-other", "HomeRegion": "us-east-1", "S3BucketName": "bucket", "S3KeyPrefix": "ct-other"},
        {"Name": "logs", "TrailARN": "arn:logs", "HomeRegion": "us-east-1", "S3BucketName": "bucket", "S3KeyPrefix": "logs"},
    ]
    ct = Mock()
    ct.describe_trails.return_value = {"trailList": trails}
    ct.get_trail_status.return_value = {"IsLogging": True}
    ct.get_event_selectors.return_value = {"EventSelectors": [], "AdvancedEventSelectors": []}
    ct.get_insight_selectors.return_value = {"InsightSelectors": []}
    ct.get_paginator.return_value.paginate.return_value = []
    s3 = Mock()
    s3.get_bucket_lifecycle_configuration.return_value = {"Rules": rules}
    monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, items: [])
    result = cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": s3}))
    by_name = {trail["Name"]: trail for trail in result["trails"]}
    assert by_name["no-prefix"]["LogBucketLifecycle"]["RetentionDays"] == 90
    assert by_name["ct-prefix"]["LogBucketLifecycle"]["RetentionDays"] == 20
    assert by_name["ct-other"]["LogBucketLifecycle"]["RetentionDays"] == 20
    assert by_name["logs"]["LogBucketLifecycle"]["RetentionDays"] is None
    assert by_name["ct-other"]["LogBucketLifecycle"]["Rules"] == rules
    s3.get_bucket_lifecycle_configuration.assert_called_once_with(Bucket="bucket")


def test_event_error_and_mfa_fields_cover_true_false_and_absent(monkeypatch):
    ct = Mock()
    ct.describe_trails.return_value = {"trailList": []}
    ct.get_paginator.return_value.paginate.return_value = [{"Events": [
        {"EventName": "ConsoleLogin", "EventTime": "2025-01-03", "CloudTrailEvent": json.dumps({"errorCode": "Failure", "userIdentity": {"sessionContext": {"attributes": {"mfaAuthenticated": "false"}}}})},
        {"EventName": "ConsoleLogin", "EventTime": "2025-01-02", "CloudTrailEvent": json.dumps({"userIdentity": {"sessionContext": {"attributes": {"mfaAuthenticated": "true"}}}})},
        {"EventName": "ConsoleLogin", "EventTime": "2025-01-01", "CloudTrailEvent": "{}"},
    ]}]
    monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, items: [])
    events = cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": Mock()}))["events"]
    assert any(event["ErrorCode"] == "Failure" and event["MFAUsed"] is False for event in events)
    assert any(event["ErrorCode"] is None and event["MFAUsed"] is True for event in events)
    assert any(event["ErrorCode"] is None and event["ErrorMessage"] is None and event["MFAUsed"] is None for event in events)


def test_insight_disabled_and_missing_lifecycle_are_not_failures(monkeypatch):
    ct = Mock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "audit", "TrailARN": "arn:trail", "HomeRegion": "us-east-1", "S3BucketName": "logs"}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    ct.get_event_selectors.return_value = {"EventSelectors": [], "AdvancedEventSelectors": []}
    ct.get_insight_selectors.side_effect = ClientError({"Error": {"Code": "InsightNotEnabledException", "Message": "not enabled"}}, "GetInsightSelectors")
    ct.get_paginator.return_value.paginate.return_value = []
    s3 = Mock()
    s3.get_bucket_lifecycle_configuration.side_effect = ClientError({"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "none"}}, "GetBucketLifecycleConfiguration")
    monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, items: [])
    trail = cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": s3}))["trails"][0]
    assert trail["InsightSelectors"] == []
    assert trail["Enrichment"]["insights"] == {"status": "complete"}
    assert trail["LogBucketLifecycle"] == {"Rules": [], "RetentionDays": None}
    assert trail["Enrichment"]["lifecycle"] == {"status": "complete"}


def test_new_operations_match_botocore_models(monkeypatch):
    ct = boto3.client("cloudtrail", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(ct) as ct_stub, Stubber(s3) as s3_stub:
        ct_stub.add_response("describe_trails", {"trailList": [{"Name": "audit", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit", "HomeRegion": "us-east-1", "S3BucketName": "logs"}]})
        ct_stub.add_response("get_trail_status", {"IsLogging": True}, {"Name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit"})
        ct_stub.add_response("get_event_selectors", {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit", "EventSelectors": [], "AdvancedEventSelectors": []}, {"TrailName": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit"})
        ct_stub.add_response("get_insight_selectors", {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit", "InsightSelectors": []}, {"TrailName": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit"})
        s3_stub.add_response("get_bucket_lifecycle_configuration", {"Rules": []}, {"Bucket": "logs"})
        for event_name in ["ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging", "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "StartInstances", "StopInstances", "TerminateInstances", "DisableKey", "ScheduleKeyDeletion"]:
            ct_stub.add_response("lookup_events", {"Events": []}, {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}], "StartTime": ANY, "EndTime": ANY})
        monkeypatch.setattr(cloudtrail, "get_all_aws_regions", lambda session: ["us-east-1"])
        monkeypatch.setattr(cloudtrail, "run_trailguard_analysis", lambda session, trails: [])
        cloudtrail.collect_cloudtrail_data(Session({"cloudtrail": ct, "s3": s3}))
        ct_stub.assert_no_pending_responses()
        s3_stub.assert_no_pending_responses()
