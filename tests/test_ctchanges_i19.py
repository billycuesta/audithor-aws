import json
import time
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from audithor.collectors import cloudtrail

NETWORK_EVENTS = [
    "CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupEgress", "ModifySecurityGroupRules", "CreateNetworkAcl",
    "CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry",
    "CreateRoute", "ReplaceRoute", "DeleteRoute", "CreateTransitGatewayRoute",
    "UpdateFirewallPolicy", "UpdateRuleGroup",
]

class Session:
    region_name = "us-east-1"
    def __init__(self, client): self.cloudtrail = client; self.client_kwargs = []
    def client(self, service, **kwargs):
        self.client_kwargs.append((service, kwargs))
        if service == "ec2": return Mock(describe_regions=lambda **kw: {"Regions": [{"RegionName": "us-east-1"}]})
        if service == "cloudtrail": return self.cloudtrail
        return Mock()

def cloudtrail_client(pages=None, error=None):
    client = Mock()
    client.describe_trails.return_value = {"trailList": []}
    client.get_paginator.return_value.paginate.return_value = pages or []
    if error: client.get_paginator.return_value.paginate.side_effect = error
    return client

def test_collects_90_day_window_and_network_events_preserving_old_event_keys():
    client = cloudtrail_client([{"Events": [{"EventName": "CreateRoute", "EventTime": datetime(2025, 1, 1, tzinfo=timezone.utc), "CloudTrailEvent": json.dumps({"awsRegion": "us-east-1", "requestParameters": {"routeTableId": "rtb-1"}})}]}])
    result = cloudtrail.collect_cloudtrail_data(Session(client))
    assert cloudtrail.LOOKUP_WINDOW_DAYS == 90
    assert result["LookupWindowDays"] == 90
    assert set(result) == {"trails", "events", "trailguard_findings", "LookupWindowDays", "Enrichment"}
    assert result["events"][0]["EventName"] == "CreateRoute"
    assert result["events"][0]["EventRegion"] == "us-east-1"
    assert result["events"][0]["SourceIPAddress"] == "N/A"
    assert result["events"][0]["RequestParameters"] == {"routeTableId": "rtb-1"}
    assert result["events"][0]["ErrorCode"] is None
    assert result["events"][0]["ErrorMessage"] is None
    assert result["events"][0]["MFAUsed"] is None
    assert set(NETWORK_EVENTS).issubset({call.kwargs["LookupAttributes"][0]["AttributeValue"] for call in client.get_paginator.return_value.paginate.call_args_list})
    args = client.get_paginator.return_value.paginate.call_args.kwargs
    assert (args["EndTime"] - args["StartTime"]).days == 90

def test_lookup_uses_adaptive_retries_and_never_sleeps(monkeypatch):
    client = cloudtrail_client([{"Events": []}])
    session = Session(client)
    monkeypatch.setattr(time, "sleep", Mock(side_effect=AssertionError("collector must not sleep")))
    cloudtrail.collect_cloudtrail_data(session)
    config = next(kwargs["config"] for service, kwargs in session.client_kwargs if service == "cloudtrail" and "config" in kwargs)
    assert config.retries["mode"] == "adaptive"
    assert config.retries["max_attempts"] == 5

def test_lookup_access_denied_is_reported_as_enrichment_failure():
    denied = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "LookupEvents")
    client = cloudtrail_client(error=denied)
    result = cloudtrail.collect_cloudtrail_data(Session(client))
    assert result["Enrichment"]["events"] == {"status": "failed", "regions": {"us-east-1": {"status": "failed", "reason": "permission_denied"}}}

def test_lookup_uses_real_cloudtrail_model_through_collector():
    client = boto3.client("cloudtrail", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    now = datetime.now(timezone.utc)
    event = {"EventId": "event-1", "EventName": "CreateRoute", "ReadOnly": "false", "AccessKeyId": "", "EventTime": now, "EventSource": "ec2.amazonaws.com", "Username": "auditor", "Resources": [], "CloudTrailEvent": json.dumps({"awsRegion": "us-east-1", "requestParameters": {}})}
    with Stubber(client) as stub:
        stub.add_response("describe_trails", {"trailList": []})
        stub.add_client_error("lookup_events", service_error_code="AccessDeniedException", http_status_code=403)
        result = cloudtrail.collect_cloudtrail_data(Session(client))
        stub.assert_no_pending_responses()
    assert result["LookupWindowDays"] == 90
    assert result["Enrichment"]["events"]["regions"]["us-east-1"]["reason"] == "permission_denied"
