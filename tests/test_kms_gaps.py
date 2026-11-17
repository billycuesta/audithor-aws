import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from unittest.mock import Mock

from audithor.collectors import kms


class Session:
    def __init__(self, client):
        self.client_value = client

    def client(self, service, **kwargs):
        return self.client_value


def fixture_client(describe):
    client = Mock()
    client.get_paginator.side_effect = lambda name: Mock(**{"paginate.return_value": [{
        "Aliases": [{"AliasName": "alias/test", "TargetKeyId": "key-1"}]
    }] if name == "list_aliases" else [{"Keys": [{"KeyId": "key-1"}]}]})
    client.describe_key.return_value = describe
    client.get_key_policy.return_value = {"Policy": "{}"}
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    return client


def test_key_metadata_is_collected_and_existing_keys_are_unchanged(monkeypatch):
    monkeypatch.setattr(kms, "get_all_aws_regions", lambda session: ["us-east-1"])
    client = fixture_client({"KeyMetadata": {"KeyId": "key-1", "Arn": "arn:key", "KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]}})
    key = kms.collect_kms_data(Session(client))["keys"][0]
    assert key["KeySpec"] == "SYMMETRIC_DEFAULT"
    assert key["KeyUsage"] == "ENCRYPT_DECRYPT"
    assert key["EncryptionAlgorithms"] == ["SYMMETRIC_DEFAULT"]
    assert key["Enrichment"]["keyMetadata"] == {"status": "complete"}
    assert {name: key[name] for name in ("Region", "KeyId", "ARN", "Aliases", "Status", "Origin", "KeyManager", "RotationEnabled", "Policy")} == {
        "Region": "us-east-1", "KeyId": "key-1", "ARN": "arn:key", "Aliases": "alias/test", "Status": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "RotationEnabled": "Enabled", "Policy": {}}


def test_describe_access_denied_records_metadata_failure(monkeypatch):
    monkeypatch.setattr(kms, "get_all_aws_regions", lambda session: ["us-east-1"])
    client = fixture_client({})
    client.describe_key.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeKey")
    key = kms.collect_kms_data(Session(client))["keys"][0]
    assert key["Enrichment"]["keyMetadata"]["status"] == "failed"
    assert key["Enrichment"]["keyMetadata"]["reason"] == "permission_denied"
    assert key["KeySpec"] is None
    assert key["KeyId"] == "key-1"
    assert key["Region"] == "us-east-1"
    assert key["Aliases"] == "alias/test"


def test_describe_key_response_shape_matches_botocore_model(monkeypatch):
    monkeypatch.setattr(kms, "get_all_aws_regions", lambda session: ["us-east-1"])
    client = boto3.client("kms", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(client) as stub:
        stub.add_response("list_aliases", {"Aliases": []}, {})
        stub.add_response("list_keys", {"Keys": [{"KeyId": "key-1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"}]}, {})
        stub.add_response("describe_key", {"KeyMetadata": {"AWSAccountId": "123456789012", "KeyId": "key-1", "Arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", "CreationDate": 1.0, "Enabled": True, "Description": "", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]}}, {"KeyId": "key-1"})
        stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": True}, {"KeyId": "key-1"})
        stub.add_response("get_key_policy", {"Policy": "{}"}, {"KeyId": "key-1", "PolicyName": "default"})
        result = kms.collect_kms_data(Session(client))
        stub.assert_no_pending_responses()
    assert result["keys"][0]["EncryptionAlgorithms"] == ["SYMMETRIC_DEFAULT"]
