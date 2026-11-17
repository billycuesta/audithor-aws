from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber, ANY

from audithor.collectors import compute


class Session:
    region_name = "us-east-1"

    def __init__(self, cloudwatch=None, functions=None):
        self.cloudwatch = cloudwatch or Mock()
        self.functions = functions or [{
            "FunctionName": "unsafe-function-name!", "FunctionArn": "arn:lambda", "Role": "arn:role"
        }]

    def client(self, service, **kwargs):
        client = Mock()
        if service == "ec2":
            client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
            client.get_paginator.return_value.paginate.return_value = []
            client.describe_images.return_value = {"Images": []}
            return client
        if service == "lambda":
            client.get_paginator.return_value.paginate.return_value = [{"Functions": self.functions}]
            return client
        if service == "cloudwatch":
            return self.cloudwatch
        if service in {"eks", "ecs"}:
            client.get_paginator.return_value.paginate.return_value = []
            return client
        if service == "sts":
            client.get_caller_identity.return_value = {"Account": "123456789012"}
        elif service in {"eks", "ecs"}:
            client.get_paginator.return_value.paginate.return_value = []
        return client

    def get_available_regions(self, service, **kwargs):
        return ["us-east-1"]

    def get_partition_for_region(self, region):
        return "aws"


def test_lambda_activity_sums_daily_points_and_maps_safe_query_ids():
    cloudwatch = Mock()
    cloudwatch.get_metric_data.return_value = {"MetricDataResults": [{
        "Id": "f0", "Timestamps": [datetime(2026, 1, 2, tzinfo=timezone.utc), datetime(2026, 1, 1, tzinfo=timezone.utc)],
        "Values": [0.0, 3.0]
    }]}
    result = compute.collect_compute_data(Session(cloudwatch))
    function = result["lambda_functions"][0]
    assert function["Invocations90d"] == 3.0
    assert function["LastInvocationDate"] == "2026-01-01"
    assert function["Enrichment"]["activity"] == {"status": "complete"}
    assert function["FunctionName"] == "unsafe-function-name!"
    call = cloudwatch.get_metric_data.call_args.kwargs
    query = call["MetricDataQueries"][0]
    assert query["Id"] == "f0"
    assert query["MetricStat"]["Metric"]["Namespace"] == "AWS/Lambda"
    assert query["MetricStat"]["Metric"]["MetricName"] == "Invocations"
    assert query["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "FunctionName", "Value": "unsafe-function-name!"}]
    assert query["MetricStat"]["Period"] == 86400
    assert query["MetricStat"]["Stat"] == "Sum"
    assert abs((call["EndTime"] - call["StartTime"]).total_seconds() - 90 * 86400) < 1
    assert result["ec2_instances"] == [] and result["eks_clusters"] == [] and result["ecs_clusters"] == []


def test_lambda_activity_follows_next_token_and_combines_datapoints():
    cloudwatch = Mock()
    cloudwatch.get_metric_data.side_effect = [
        {"MetricDataResults": [{"Id": "f0", "Timestamps": [datetime(2026, 1, 1, tzinfo=timezone.utc)], "Values": [2.0]}], "NextToken": "page-two"},
        {"MetricDataResults": [{"Id": "f0", "Timestamps": [datetime(2026, 1, 3, tzinfo=timezone.utc)], "Values": [4.0]}]}
    ]
    result = compute.collect_compute_data(Session(cloudwatch))
    function = result["lambda_functions"][0]
    assert function["Invocations90d"] == 6.0
    assert function["LastInvocationDate"] == "2026-01-03"
    assert cloudwatch.get_metric_data.call_count == 2
    assert cloudwatch.get_metric_data.call_args_list[1].kwargs["NextToken"] == "page-two"


def test_lambda_activity_batches_501_functions_and_maps_every_query():
    functions = [{"FunctionName": f"function-{index}", "FunctionArn": f"arn:{index}"} for index in range(501)]
    cloudwatch = Mock()
    cloudwatch.get_metric_data.side_effect = lambda **request: {"MetricDataResults": [
        {"Id": query["Id"], "Timestamps": [datetime(2026, 1, 1, tzinfo=timezone.utc)], "Values": [1.0]}
        for query in request["MetricDataQueries"]
    ]}
    result = compute.collect_compute_data(Session(cloudwatch, functions))
    calls = cloudwatch.get_metric_data.call_args_list
    assert len(calls) == 2
    assert [len(call.kwargs["MetricDataQueries"]) for call in calls] == [500, 1]
    assert all(function["Invocations90d"] == 1.0 for function in result["lambda_functions"])
    assert all(function["LastInvocationDate"] == "2026-01-01" for function in result["lambda_functions"])


def test_lambda_activity_access_denied_is_enrichment_failure_and_old_keys_unchanged():
    cloudwatch = Mock()
    cloudwatch.get_metric_data.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetMetricData")
    result = compute.collect_compute_data(Session(cloudwatch))
    function = result["lambda_functions"][0]
    assert function["FunctionName"] == "unsafe-function-name!"
    assert function["Role"] == "arn:role"
    assert function["Runtime"] is None
    assert function["Enrichment"]["activity"] == {"status": "failed", "reason": "permission_denied"}
    assert "Invocations90d" not in function and "LastInvocationDate" not in function


def test_lambda_activity_uses_real_cloudwatch_service_model():
    client = boto3.client("cloudwatch", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    response = {"MetricDataResults": [{"Id": "f0", "Timestamps": [datetime(2026, 1, 1, tzinfo=timezone.utc)], "Values": [2.0], "StatusCode": "Complete"}]}
    with Stubber(client) as stub:
        stub.add_response("get_metric_data", response, expected_params={
            "MetricDataQueries": [{"Id": "f0", "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations", "Dimensions": [{"Name": "FunctionName", "Value": "unsafe-function-name!"}]}, "Period": 86400, "Stat": "Sum"}, "ReturnData": True}],
            "StartTime": ANY, "EndTime": ANY
        })
        result = compute.collect_compute_data(Session(client))
        stub.assert_no_pending_responses()
    function = result["lambda_functions"][0]
    assert function["Invocations90d"] == 2.0
    assert function["LastInvocationDate"] == "2026-01-01"
