import boto3
import pytest
from unittest.mock import Mock
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from audithor.collectors.iam import collect_iam_data

class Session:
    region_name = "us-east-1"
    def __init__(self, iam): self.iam = iam
    def client(self, service, **kwargs):
        if service == "iam": return self.iam
        if service == "sts":
            sts = Mock(); sts.get_caller_identity.return_value = {"Account": "123456789012"}; return sts
        return Mock()

def setup_client(response=None, error=False):
    iam = Mock(); iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
    iam.list_users.return_value = {"Users": []}
    iam.list_groups.return_value = {"Groups": []}
    iam.get_account_password_policy.side_effect = iam.exceptions.NoSuchEntityException()
    iam.get_account_summary.return_value = {"SummaryMap": {}}
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
    iam.list_roles.return_value = {"Roles": [{"RoleName": "AuditRole", "CreateDate": "2024-01-01"}]}
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.list_role_policies.return_value = {"PolicyNames": []}
    if error:
        iam.get_paginator.return_value.paginate.side_effect = ClientError({"Error":{"Code":"AccessDenied","Message":"denied"}}, "GetAccountAuthorizationDetails")
    else:
        iam.get_paginator.return_value.paginate.return_value = [response]
    return iam

def inventory():
    return {"RoleDetailList":[{"RoleName":"AuditRole","CreateDate":"2024-01-01","AttachedPolicies":[
        {"PolicyName":"CustomerPolicy","PolicyArn":"arn:aws:iam::123456789012:policy/CustomerPolicy"},
        {"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}],
        "RolePolicyList":[{"PolicyName":"Inline","PolicyDocument":"%7B%22Statement%22%3A%5B%5D%7D"}]}],
        "Policies":[{"Arn":"arn:aws:iam::123456789012:policy/CustomerPolicy","PolicyName":"CustomerPolicy","PolicyVersionList":[
            {"VersionId":"v1","IsDefaultVersion":False,"Document":{}},{"VersionId":"v2","IsDefaultVersion":True,"Document":{"Statement":[{"Effect":"Allow"}]}}]}]}

def test_account_authorization_details_add_documents_without_changing_existing_fields():
    iam=setup_client(inventory()); role=collect_iam_data(Session(iam))["roles"][0]
    assert role["RoleName"] == "AuditRole"
    assert role["AttachedPolicies"] == ["CustomerPolicy", "ReadOnlyAccess"]
    assert role["InlinePolicies"] == ["Inline"]
    assert role["InlinePolicyDocuments"] == [{"PolicyName":"Inline","PolicyDocument":{"Statement":[]}}]
    assert role["CustomerManagedPolicies"] == [{"PolicyName":"CustomerPolicy","PolicyArn":"arn:aws:iam::123456789012:policy/CustomerPolicy","DefaultVersionId":"v2","PolicyDocument":{"Statement":[{"Effect":"Allow"}]}}]
    assert role["Enrichment"]["policyDocuments"] == {"status":"complete"}
    iam.get_paginator.assert_called_once_with("get_account_authorization_details")
    assert iam.get_paginator.return_value.paginate.call_args.kwargs == {"Filter":["Role","LocalManagedPolicy"]}

def test_access_denied_marks_each_retained_role_failed():
    role=collect_iam_data(Session(setup_client(error=True)))["roles"][0]
    assert role["Enrichment"]["policyDocuments"] == {"status":"failed","reason":"permission_denied"}
    assert role["AttachedPolicies"] == [] and role["InlinePolicies"] == []
    assert role["InlinePolicyDocuments"] == []

def test_real_botocore_model_stubber_for_new_operation():
    client=boto3.client("iam",region_name="us-east-1",aws_access_key_id="testing",aws_secret_access_key="testing")
    # The collector's call path includes the usual IAM inventory; stub those calls before the target API.
    with Stubber(client) as stub:
        stub.add_response("list_users", {"Users":[]}, {})
        stub.add_client_error("get_account_password_policy", service_error_code="NoSuchEntity", expected_params={})
        stub.add_response("get_account_summary", {"SummaryMap":{}}, {})
        stub.add_response("list_virtual_mfa_devices", {"VirtualMFADevices":[]}, {})
        stub.add_response("get_account_authorization_details", {"RoleDetailList":[],"Policies":[],"IsTruncated":False}, {"Filter":["Role","LocalManagedPolicy"]})
        stub.add_response("list_groups", {"Groups":[]}, {})
        result=collect_iam_data(Session(client))
        stub.assert_no_pending_responses()
    assert result["roles"] == []
