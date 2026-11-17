from unittest.mock import Mock

import boto3
from botocore.stub import Stubber
from audithor.collectors import waf


def test_collected_regional_and_cloudfront_web_acl_fields(monkeypatch):
    monkeypatch.setattr(waf, "get_all_aws_regions", lambda session: ["us-west-2"])
    monkeypatch.setattr(waf, "get_cloudfront_to_waf_map", lambda session: {})
    monkeypatch.setattr(waf, "get_logging_configuration_details", lambda *args: {"all_logging": {"enabled": True}, "destination_only_logging": {"enabled": False}})
    action_rules = [
        {"Name": "managed", "Priority": 4, "Action": {"Block": {}}, "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "CommonRuleSet"}}},
        {"Name": "rate", "Priority": 1, "OverrideAction": {"None": {}}, "Statement": {"RateBasedStatement": {"Limit": 1000}}},
        {"Name": "ipset", "Priority": 3, "Action": {"Allow": {}}, "Statement": {"IPSetReferenceStatement": {"ARN": "arn:aws:wafv2:us-west-2:123456789012:regional/ipset/test/id"}}},
        {"Name": "bytes", "Priority": 2, "OverrideAction": {"Count": {}}, "Statement": {"ByteMatchStatement": {}}},
    ]
    expected_summaries = [
        "ManagedRuleGroupStatement AWS/CommonRuleSet", "RateBasedStatement limit 1000",
        "IPSetReferenceStatement arn:aws:wafv2:us-west-2:123456789012:regional/ipset/test/id", "ByteMatchStatement",
    ]
    def make_acl(name, scope):
        return {"Name": name, "Id": f"{scope}-id", "ARN": f"arn:{scope}", "DefaultAction": {"Allow": {}},
                "Capacity": 29, "Rules": action_rules, "LoggingConfiguration": {"Enabled": True},
                "VisibilityConfig": {"SampledRequestsEnabled": True}}
    global_summary = {"Name": "global", "Id": "CLOUDFRONT-id", "ARN": "arn:CLOUDFRONT"}
    regional_summary = {"Name": "regional", "Id": "REGIONAL-id", "ARN": "arn:REGIONAL"}
    class WafClient:
        def list_web_acls(self, Scope):
            return {"WebACLs": [global_summary] if Scope == "CLOUDFRONT" else [regional_summary]}
        def get_web_acl(self, Name, Scope, Id):
            return {"WebACL": make_acl(Name, Scope)}
        def list_resources_for_web_acl(self, **kwargs): return {"ResourceArns": ["arn:resource"]}
        def list_ip_sets(self, **kwargs): return {"IPSets": []}
    class Session:
        def client(self, service, **kwargs):
            if service == "wafv2": return WafClient()
            mock = Mock()
            if service in {"waf", "waf-regional"}: mock.list_web_acls.return_value = {"WebACLs": []}
            if service == "cloudfront": mock.get_paginator.return_value.paginate.return_value = []
            if service == "cloudwatch": mock.get_metric_data.return_value = {"MetricDataResults": []}
            if service == "elbv2": mock.get_paginator.return_value.paginate.return_value = []
            if service == "apigateway": mock.get_rest_apis.return_value = {"items": []}
            if service == "sts": mock.get_caller_identity.return_value = {"Account": "123456789012"}
            return mock
    result = waf.collect_waf_data(Session())
    assert [acl["Name"] for acl in result["acls"]] == ["global", "regional"]
    for acl in result["acls"]:
        assert acl["DefaultAction"] == {"Allow": {}}
        assert acl["Capacity"] == 29
        assert [rule["StatementSummary"] for rule in acl["Rules"]] == expected_summaries
        assert [rule.get("Action", rule.get("OverrideAction")) for rule in acl["Rules"]] == [
            {"Block": {}}, {"None": {}}, {"Allow": {}}, {"Count": {}}]
        assert acl["Enrichment"] == {"rules": {"status": "complete"}}
        assert acl["LoggingConfiguration"] == {"Enabled": True}
        assert acl["LoggingDetails"] == {"all_logging": {"enabled": True}, "destination_only_logging": {"enabled": False}}
        assert acl["VisibilityConfig"] == {"SampledRequestsEnabled": True}
        assert acl["TopRules"] == []
        assert acl["AssociatedResourceArns"] == ["arn:resource"]


def test_get_web_acl_shape_and_rule_extraction():
    client = boto3.client("wafv2", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    acl_arn = "arn:aws:wafv2:us-east-1:123456789012:regional/web/id"
    response = {"WebACL": {"Name": "web", "Id": "id", "ARN": acl_arn, "DefaultAction": {"Allow": {}}, "Capacity": 17,
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "web"},
        "Rules": [{"Name": "managed", "Priority": 2, "OverrideAction": {"None": {}}, "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "CommonRuleSet"}},
        "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "managed"}}]}}
    with Stubber(client) as stub:
        stub.add_response("get_web_acl", response, {"Name": "web", "Scope": "REGIONAL", "Id": "id"})
        web_acl = client.get_web_acl(Name="web", Scope="REGIONAL", Id="id")["WebACL"]
        stub.assert_no_pending_responses()
    details = waf._extract_web_acl_details(web_acl)
    assert details == {"DefaultAction": {"Allow": {}}, "Capacity": 17,
                       "Rules": [{"Name": "managed", "Priority": 2, "OverrideAction": {"None": {}},
                                  "StatementSummary": "ManagedRuleGroupStatement AWS/CommonRuleSet"}]}
    assert "LoggingConfiguration" not in details and "VisibilityConfig" not in details
