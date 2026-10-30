import io
import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError
from botocore.stub import Stubber
from collectors import acm, databases, inspector
from collectors.diagnostics import Collection, classify_error


def error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "SECRET_DO_NOT_LOG"},
                        "ResponseMetadata": {"RequestId": "request-123", "HTTPStatusCode": 403}}, "Test")


class Session:
    region_name = "us-east-1"
    _audithor_account_id = "123456789012"
    _audithor_scan_id = "af5516eb-9b24-47e2-9cf0-bd76c297845c"

    def __init__(self, clients=None, regions=None):
        self.clients = clients or {}
        self.region_map = regions or {"us-east-1": "opt-in-not-required"}
        self.ec2 = Mock()
        self.ec2.describe_regions.return_value = {"Regions": [dict(RegionName=k, OptInStatus=v) for k,v in self.region_map.items()]}

    def get_partition_for_region(self, region):
        return "aws"

    def get_available_regions(self, service, **kwargs):
        return list(self.region_map)

    def client(self, service, **kwargs):
        return self.clients.get(service, self.ec2 if service == "ec2" else Mock())


def paginator_client(pages):
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = pages
    return client


@pytest.mark.parametrize("exc,category", [
    (error(), "permission_denied"), (error("SignatureDoesNotMatch"), "authentication_error"),
    (error("InvalidClientTokenId"), "authentication_error"),
    (EndpointConnectionError(endpoint_url="https://example.invalid"), "connectivity_error"),
    (ConnectTimeoutError(endpoint_url="https://example.invalid"), "connectivity_error"),
    (ReadTimeoutError(endpoint_url="https://example.invalid"), "connectivity_error"),
    (error("ThrottlingException"), "throttled"), (error("OptInRequired"), "region_not_enabled")])
def test_classifier(exc, category):
    assert classify_error(exc)["category"] == category


def test_disabled_region_is_not_contacted():
    client = paginator_client([])
    session = Session({"acm": client}, {"me-south-1": "not-opted-in"})
    result = acm.collect_acm_data_web(session)
    client.get_paginator.assert_not_called()
    assert result["_collection"]["status"] == "not_applicable"
    assert result["_collection"]["units"][-1]["category"] == "region_not_enabled"


def test_discovery_failure_is_explicit_and_fallback_runs():
    session = Session({"acm": paginator_client([])})
    session.ec2.describe_regions.side_effect = error()
    result = acm.collect_acm_data_web(session)
    assert result["_collection"]["coverageKnown"] is False
    assert result["_collection"]["status"] == "partial"


def test_all_inventory_operations_failed():
    client = Mock()
    client.get_paginator.side_effect = error()
    result = acm.collect_acm_data_web(Session({"acm": client}))
    assert result["_collection"]["status"] == "failed"
    assert result["certificates"] == []


def test_page_failure_retains_prior_resources():
    def pages():
        yield {"CertificateSummaryList": [{"CertificateArn": "arn:cert", "DomainName": "example.org"}]}
        raise EndpointConnectionError(endpoint_url="https://example.invalid")
    client = paginator_client(pages())
    client.describe_certificate.return_value = {"Certificate": {"CertificateArn": "arn:cert"}}
    result = acm.collect_acm_data_web(Session({"acm": client}))
    assert len(result["certificates"]) == 1
    assert result["_collection"]["status"] == "partial"


def test_acm_resource_permission_error_preserves_summary_and_request_id(caplog):
    client = paginator_client([{"CertificateSummaryList": [{"CertificateArn": "arn:cert"}]}])
    client.describe_certificate.side_effect = error()
    # audithor_app disables propagation, so capture on the named logger itself.
    logger = logging.getLogger("audithor.collection")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    try:
        with caplog.at_level("INFO", logger=logger.name):
            result = acm.collect_acm_data_web(Session({"acm": client}))
    finally:
        logger.removeHandler(handler)
    assert result["certificates"][0]["DetailsStatus"] == "unknown"
    failed = next(u for u in result["_collection"]["units"] if u["status"] == "failed")
    assert failed["awsRequestId"] == "request-123"
    assert "SECRET_DO_NOT_LOG" not in stream.getvalue()
    assert "request-123" in stream.getvalue()


def test_acm_real_botocore_stubber():
    client = boto3.client("acm", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(client) as stub:
        stub.add_client_error("list_certificates", service_error_code="AccessDeniedException", http_status_code=403)
        result = acm.collect_acm_data_web(Session({"acm": client}))
        stub.assert_no_pending_responses()
    assert result["_collection"]["status"] == "failed"


def test_rds_failure_does_not_skip_dynamodb_or_documentdb():
    rds = Mock()
    rds.get_paginator.side_effect = error()
    dynamo = paginator_client([{"TableNames": ["table"]}])
    dynamo.describe_table.return_value = {"Table": {"TableName": "table", "TableArn": "arn:table"}}
    docdb = paginator_client([])
    kms = paginator_client([])
    result = databases.collect_database_data(Session({"rds": rds, "dynamodb": dynamo, "docdb": docdb, "kms": kms}))
    assert result["dynamodb_tables"][0]["TableName"] == "table"
    docdb.get_paginator.assert_called_once_with("describe_db_clusters")
    assert result["_collection"]["status"] == "partial"


def test_subnet_error_remains_unknown():
    rds = Mock()
    rds.get_paginator.side_effect = lambda op: SimpleNamespace(paginate=lambda: iter([
        {"DBInstances": [{"DBInstanceIdentifier": "db", "DBSubnetGroup": {"DBSubnetGroupName": "group"}}]}
        if op == "describe_db_instances" else {"DBClusters": []}]))
    rds.describe_db_subnet_groups.side_effect = error()
    session = Session({"rds": rds, "dynamodb": paginator_client([]), "docdb": paginator_client([]), "kms": paginator_client([])})
    result = databases.collect_database_data(session)
    assert result["rds_instances"][0]["SubnetIds"] is None
    assert result["rds_instances"][0]["NetworkDetailsStatus"] == "unknown"
    assert result["_collection"]["status"] == "partial"


def test_inspector_failed_accounts_http_200_is_failure():
    client = Mock()
    client.batch_get_account_status.return_value = {"accounts": [], "failedAccounts": [
        {"accountId": "123456789012", "errorCode": "ACCESS_DENIED", "errorMessage": "secret"}]}
    result = inspector.collect_inspector_status(Session({"inspector2": client}))
    assert result["_collection"]["status"] == "failed"
    assert result["findingsStatus"] == "not_run"


def test_inspector_disabled_is_visible():
    client = Mock()
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012", "state": {"status": "DISABLED"}}]}
    session = Session({"inspector2": client})
    result = inspector.collect_inspector_status(session)
    assert result["scan_status"][0]["InspectorStatus"] == "DISABLED"
    assert result["_collection"]["status"] == "complete"
    findings = inspector.collect_inspector_findings(session)
    assert findings["_collection"]["status"] == "not_applicable"
    client.get_paginator.assert_not_called()


def test_enrichment_failure_preserves_findings():
    client = paginator_client([{"findings": [{"severity": "HIGH", "resources": [{"type": "AWS_EC2_INSTANCE", "id": "i-123"}]}]}])
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012", "state": {"status": "ENABLED"}}]}
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}
    ec2.get_paginator.side_effect = error()
    result = inspector.collect_inspector_findings(Session({"inspector2": client, "ec2": ec2}))
    assert result["findings"][0]["resourceNameStatus"] == "unknown"
    assert result["_collection"]["status"] == "partial"


def test_dynamodb_connectivity_failure_stops_details_and_retains_page():
    dynamo = paginator_client([{"TableNames": ["one", "two", "three"]}])
    dynamo.describe_table.side_effect = EndpointConnectionError(endpoint_url="https://example.invalid")
    result = databases.collect_database_data(Session({"rds": paginator_client([]), "dynamodb": dynamo, "docdb": paginator_client([]), "kms": paginator_client([])}))
    dynamo.describe_table.assert_called_once()
    assert [t["TableName"] for t in result["dynamodb_tables"]] == ["one", "two", "three"]
    assert all(t["DetailsStatus"] == "unknown" and t["Encrypted"] is None for t in result["dynamodb_tables"])
    assert result["_collection"]["status"] == "partial"


def test_acm_connectivity_failure_stops_details_and_retains_page():
    summaries = [{"CertificateArn": f"arn:{name}"} for name in ("one", "two", "three")]
    client = paginator_client([{"CertificateSummaryList": summaries}])
    client.describe_certificate.side_effect = EndpointConnectionError(endpoint_url="https://example.invalid")
    result = acm.collect_acm_data_web(Session({"acm": client}))
    client.describe_certificate.assert_called_once()
    assert [c["CertificateArn"] for c in result["certificates"]] == [s["CertificateArn"] for s in summaries]
    assert all(c["DetailsStatus"] == "unknown" for c in result["certificates"])
    assert result["_collection"]["status"] == "partial"


def test_acm_summary_datetime_fallback_is_json_safe():
    from datetime import datetime, timezone
    summary = {"CertificateArn": "arn:cert", "IssuedAt": datetime(2024, 1, 2, tzinfo=timezone.utc),
               "NotAfter": datetime(2025, 1, 2, tzinfo=timezone.utc)}
    client = paginator_client([{"CertificateSummaryList": [summary]}])
    client.describe_certificate.side_effect = error()
    result = acm.collect_acm_data_web(Session({"acm": client}))
    assert result["certificates"][0]["IssuedAt"] == "2024-01-02T00:00:00+00:00"
    assert result["certificates"][0]["NotAfter"] == "2025-01-02T00:00:00+00:00"
    json.dumps(result)


def test_diagnostics_bootstrap_uses_configured_region():
    session = Session()
    session.region_name = "cn-north-1"
    calls = []
    original = session.client
    def capture(service, **kwargs):
        calls.append((service, kwargs))
        return original(service, **kwargs)
    session.client = capture
    Collection("test", session).regions(session, "acm")
    assert next(kwargs["region_name"] for service, kwargs in calls if service == "ec2") == "cn-north-1"


def test_failed_nested_operation_suppresses_parent_complete_unit():
    client = paginator_client([{"CertificateSummaryList": [{"CertificateArn": "arn:cert"}]}])
    client.describe_certificate.side_effect = error()
    result = acm.collect_acm_data_web(Session({"acm": client}))
    units = result["_collection"]["units"]
    assert any(u["operation"] == "describe_certificate" and u["status"] == "failed" for u in units)
    assert not any(u["operation"] == "list_certificates" and u["status"] == "complete" for u in units)


def test_inspector_describes_instances_in_named_batches():
    ids = [f"i-{number:03d}" for number in range(101)]
    client = paginator_client([{"findings": [{"severity": "HIGH", "resources": [
        {"type": "AWS_EC2_INSTANCE", "id": instance_id}]} for instance_id in ids]}])
    client.batch_get_account_status.return_value = {"accounts": [{"accountId": "123456789012", "state": {"status": "ENABLED"}}]}
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}
    ec2.get_paginator.return_value.paginate.return_value = []
    inspector.collect_inspector_findings(Session({"inspector2": client, "ec2": ec2}))
    calls = ec2.get_paginator.return_value.paginate.call_args_list
    assert [len(call.kwargs["InstanceIds"]) for call in calls] == [100, 1]


def test_json_round_trip_retains_coverage():
    result = acm.collect_acm_data_web(Session({"acm": paginator_client([])}))
    assert json.loads(json.dumps(result))["_collection"] == result["_collection"]


def test_service_availability_is_independent_of_region_enablement():
    session = Session(regions={"us-east-1": "opt-in-not-required", "eu-west-1": "opt-in-not-required"})
    session.get_available_regions = lambda service, **kwargs: ["us-east-1"]
    diag = Collection("test", session)
    assert diag.regions(session, "docdb") == ["us-east-1"]
    assert any(u.get("category") == "service_not_available" and u["region"] == "eu-west-1" for u in diag.units)


def test_empty_sdk_catalog_is_not_complete_or_not_applicable():
    session = Session()
    session.get_available_regions = lambda service, **kwargs: []
    diag = Collection("test", session)
    assert diag.regions(session, "acm") == []
    result = diag.finish({"certificates": []})
    assert result["_collection"]["coverageKnown"] is False
    assert result["_collection"]["status"] == "failed"


def test_dynamodb_resource_error_does_not_skip_other_tables():
    dynamo = paginator_client([{"TableNames": ["failed", "good"]}])
    dynamo.describe_table.side_effect = [error(), {"Table": {"TableName": "good"}}]
    session = Session({"rds": paginator_client([]), "dynamodb": dynamo, "docdb": paginator_client([]), "kms": paginator_client([])})
    result = databases.collect_database_data(session)
    assert [t["TableName"] for t in result["dynamodb_tables"]] == ["failed", "good"]
    assert result["dynamodb_tables"][0]["Encrypted"] is None
    assert result["_collection"]["status"] == "partial"
