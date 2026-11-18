import json
from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from audithor.collectors.organizations import collect_region_guardrails


class Session:
    def __init__(self, client):
        self.client_instance = client

    def client(self, service, **kwargs):
        assert service == "organizations"
        assert kwargs["region_name"] == "us-east-1"
        return self.client_instance


def test_collects_region_scp_and_targets_and_preserves_existing_keys():
    client = Mock()
    client.describe_organization.return_value = {"Organization": {"Id": "o-example", "MasterAccountId": "111111111111"}}
    client.get_paginator.side_effect = lambda operation: Mock(paginate=Mock(return_value={
        "list_policies": [{"Policies": [{"Id": "p-region", "Name": "Region policy"}]}],
        "list_targets_for_policy": [{"Targets": [{"TargetId": "ou-root", "Name": "Root", "Type": "ROOT"}]}],
    }[operation]))
    client.describe_policy.return_value = {"Policy": {"Content": json.dumps({"Statement": {
        "Effect": "Deny", "Action": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}}, "NotAction": ["iam:*"]
    }})}}
    existing = {"users": ["unchanged"]}
    existing["region_guardrails"] = collect_region_guardrails(Session(client))
    assert existing["users"] == ["unchanged"]
    guardrails = existing["region_guardrails"]
    assert guardrails["OrganizationId"] == "o-example"
    assert guardrails["MasterAccountId"] == "111111111111"
    policy = guardrails["Policies"][0]
    assert policy["PolicyId"] == "p-region"
    assert policy["Name"] == "Region policy"
    assert policy["AllowedRegions"] == ["us-east-1", "eu-west-1"]
    assert policy["DeniedRegions"] == []
    assert policy["ExemptActions"] == ["iam:*"]
    assert policy["Targets"] == [{"TargetId": "ou-root", "Name": "Root", "Type": "ROOT"}]
    assert guardrails["Enrichment"]["regionGuardrails"]["status"] == "complete"


def test_access_denied_reports_failed_without_data():
    client = Mock()
    client.describe_organization.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeOrganization")
    result = collect_region_guardrails(Session(client))
    assert "OrganizationId" not in result and "Policies" not in result
    assert result["Enrichment"]["regionGuardrails"] == {"status": "failed", "reason": "permission_denied"}


def test_organizations_not_in_use_is_skipped_with_exact_reason():
    client = Mock()
    client.describe_organization.side_effect = ClientError(
        {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "not enabled"}},
        "DescribeOrganization")
    result = collect_region_guardrails(Session(client))
    assert result["Enrichment"]["regionGuardrails"] == {
        "status": "skipped", "reason": "organizations_not_in_use"}
    assert "Policies" not in result


def test_access_denied_listing_policies_is_failed():
    client = Mock()
    client.describe_organization.return_value = {"Organization": {"Id": "o-example", "MasterAccountId": "111111111111"}}
    client.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListPolicies")
    result = collect_region_guardrails(Session(client))
    assert result["Enrichment"]["regionGuardrails"] == {"status": "failed", "reason": "permission_denied"}
    assert "Policies" not in result


def test_allow_statement_with_requested_region_is_not_a_guardrail():
    client = Mock()
    client.describe_organization.return_value = {"Organization": {"Id": "o-example", "MasterAccountId": "111111111111"}}
    client.get_paginator.return_value.paginate.return_value = [{"Policies": [{"Id": "p-allow", "Name": "Allow policy"}]}]
    client.describe_policy.return_value = {"Policy": {"Content": json.dumps({"Statement": {
        "Effect": "Allow", "Action": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    }})}}
    result = collect_region_guardrails(Session(client))
    assert result["Policies"] == []
    client.get_paginator.assert_called_once_with("list_policies")
    assert client.get_paginator.call_args_list[0].kwargs == {}


def test_stubber_uses_real_describe_organization_shape_through_collector():
    client = boto3.client("organizations", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(client) as stub:
        stub.add_response("describe_organization", {"Organization": {"Id": "o-example", "Arn": "arn:aws:organizations::111111111111:organization/o-example", "FeatureSet": "ALL", "MasterAccountArn": "arn:aws:organizations::111111111111:account/o-example/111111111111", "MasterAccountId": "111111111111", "MasterAccountEmail": "owner@example.com"}})
        stub.add_response("list_policies", {"Policies": [{"Id": "p-example", "Arn": "arn:aws:organizations::111111111111:policy/o-example/service_control_policy/p-example", "Name": "Region policy", "Description": "Region guardrail", "Type": "SERVICE_CONTROL_POLICY", "AwsManaged": False}], "NextToken": ""}, {"Filter": "SERVICE_CONTROL_POLICY"})
        content = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}}]})
        stub.add_response("describe_policy", {"Policy": {"PolicySummary": {"Id": "p-example", "Arn": "arn:aws:organizations::111111111111:policy/o-example/service_control_policy/p-example", "Name": "Region policy", "Description": "Region guardrail", "Type": "SERVICE_CONTROL_POLICY", "AwsManaged": False}, "Content": content}}, {"PolicyId": "p-example"})
        stub.add_response("list_targets_for_policy", {"Targets": [{"TargetId": "ou-root", "Arn": "arn:aws:organizations::111111111111:root/o-example/r-example", "Name": "Root", "Type": "ROOT"}], "NextToken": ""}, {"PolicyId": "p-example"})
        result = collect_region_guardrails(Session(client))
        stub.assert_no_pending_responses()
    assert result["Policies"][0]["Targets"][0]["Type"] == "ROOT"
    assert result["Enrichment"]["regionGuardrails"]["status"] == "complete"
