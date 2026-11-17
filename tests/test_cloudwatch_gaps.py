from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from audithor.collectors import cloudwatch


class Session:
    def __init__(self, clients):
        self.clients = clients
    def get_credentials(self):
        return Mock(access_key='a', secret_key='b', token='c')
    def client(self, service, **kwargs):
        return self.clients[service]


def test_collects_log_groups_filters_and_all_topic_subscriptions(monkeypatch):
    logs = Mock()
    logs.get_paginator.side_effect = lambda op: Mock(paginate=Mock(return_value=[
        {'logGroups': [{'logGroupName': 'app', 'retentionInDays': 30, 'kmsKeyId': 'key', 'storedBytes': 5, 'creationTime': 123}]}
    ] if op == 'describe_log_groups' else [{'metricFilters': [{'filterName': 'errors', 'filterPattern': '<img src=x onerror=alert(1)>', 'metricTransformations': []}]}]))
    sns = Mock()
    sns.get_paginator.side_effect = lambda op: Mock(paginate=Mock(return_value=[{'Topics': [{'TopicArn': 'arn:topic'}]}] if op == 'list_topics' else [{'Subscriptions': [
        {'Protocol': 'email', 'Endpoint': 'a@example.com', 'SubscriptionArn': 'arn:sub'},
        {'Protocol': 'https', 'Endpoint': 'https://example.com', 'SubscriptionArn': 'PendingConfirmation'}
    ]}]))
    cw = Mock()
    cw.get_paginator.return_value.paginate.return_value = [{'MetricAlarms': []}]
    monkeypatch.setattr(cloudwatch, 'get_all_aws_regions', lambda _: ['us-east-1'])
    monkeypatch.setattr(cloudwatch.boto3, 'Session', lambda **kwargs: Session({'logs': logs, 'sns': sns, 'cloudwatch': cw}))
    result = cloudwatch.collect_cloudwatch_data(Session({}))
    assert result['alarms'] == []
    assert result['topics'][0]['TopicArn'] == 'arn:topic'
    assert result['topics'][0]['Subscriptions'] == [
        {'Endpoint': 'a@example.com', 'Protocol': 'email', 'Status': 'Confirmed'},
        {'Endpoint': 'https://example.com', 'Protocol': 'https', 'Status': 'Pending'}]
    assert result['topics'][0]['Enrichment']['subscriptions'] == {'status': 'complete'}
    assert result['logGroups'][0]['logGroupName'] == 'app'
    assert result['logGroups'][0]['retentionInDays'] == 30
    assert result['logGroups'][0]['kmsKeyId'] == 'key'
    assert result['logGroups'][0]['storedBytes'] == 5
    assert result['logGroups'][0]['creationTime'] == 123
    assert result['Enrichment']['logGroups'] == {'status': 'complete', 'regions': {'us-east-1': {'status': 'complete'}}}
    assert len(result['logGroups']) == 1
    assert result['metricFilters'][0]['FilterPattern'] == '<img src=x onerror=alert(1)>'
    assert result['Enrichment']['metricFilters'] == {'status': 'complete', 'regions': {'us-east-1': {'status': 'complete'}}}
    assert result['topics'][0]['Subscriptions'][1]['Status'] == 'Pending'


def test_log_group_access_denied_records_enrichment_failure(monkeypatch):
    logs = Mock()
    def denied_paginator(op):
        paginator = Mock()
        paginator.paginate.side_effect = ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'denied'}}, 'DescribeLogGroups' if op == 'describe_log_groups' else 'DescribeMetricFilters')
        return paginator
    logs.get_paginator.side_effect = denied_paginator
    sns = Mock()
    def sns_paginator(op):
        paginator = Mock()
        if op == 'list_topics':
            paginator.paginate.return_value = [{'Topics': [{'TopicArn': 'arn:topic'}]}]
        else:
            paginator.paginate.side_effect = ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'denied'}}, 'ListSubscriptionsByTopic')
        return paginator
    sns.get_paginator.side_effect = sns_paginator
    cw = Mock()
    cw.get_paginator.return_value.paginate.return_value = [{'MetricAlarms': []}]
    monkeypatch.setattr(cloudwatch, 'get_all_aws_regions', lambda _: ['us-east-1'])
    monkeypatch.setattr(cloudwatch.boto3, 'Session', lambda **kwargs: Session({'logs': logs, 'sns': sns, 'cloudwatch': cw}))
    result = cloudwatch.collect_cloudwatch_data(Session({}))
    assert result['alarms'] == [] and len(result['topics']) == 1
    assert result['logGroups'] == []
    assert result['Enrichment']['logGroups'] == {'status': 'failed', 'regions': {'us-east-1': {'status': 'failed', 'reason': 'permission_denied'}}}
    assert result['Enrichment']['metricFilters'] == {'status': 'failed', 'regions': {'us-east-1': {'status': 'failed', 'reason': 'permission_denied'}}}
    assert result['topics'][0]['Enrichment']['subscriptions'] == {'status': 'failed', 'reason': 'permission_denied'}


def test_describe_log_groups_stubbed_through_collector(monkeypatch):
    client = boto3.client('logs', region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    sns = Mock(); sns.get_paginator.return_value.paginate.return_value = []
    cw = Mock(); cw.get_paginator.return_value.paginate.return_value = [{'MetricAlarms': []}]
    monkeypatch.setattr(cloudwatch, 'get_all_aws_regions', lambda _: ['us-east-1'])
    monkeypatch.setattr(cloudwatch.boto3, 'Session', lambda **kwargs: Session({'logs': client, 'sns': sns, 'cloudwatch': cw}))
    with Stubber(client) as stub:
        stub.add_response('describe_log_groups', {'logGroups': [{'logGroupName':'stub', 'creationTime':123, 'storedBytes':0, 'kmsKeyId':'key', 'retentionInDays':7}], 'nextToken':'next'})
        stub.add_response('describe_log_groups', {'logGroups': []})
        stub.add_response('describe_metric_filters', {'metricFilters': []})
        result = cloudwatch.collect_cloudwatch_data(Session({}))
        stub.assert_no_pending_responses()
    assert result['logGroups'][0]['logGroupName'] == 'stub'
