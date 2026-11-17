from unittest.mock import Mock

from botocore.exceptions import ClientError
from botocore.stub import Stubber
import boto3

from audithor.collectors import databases
from test_collection import Session, paginator_client


def test_dynamodb_enrichments_preserve_existing_fields():
    dynamo = paginator_client([{"TableNames": ["ledger"]}])
    dynamo.describe_table.return_value = {"Table": {"TableName": "ledger", "TableStatus": "ACTIVE", "ItemCount": 4, "TableSizeBytes": 20, "TableArn": "arn:table", "SSEDescription": {"Status": "ENABLED", "KMSMasterKeyArn": "arn:key"}, "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}], "DeletionProtectionEnabled": True}}
    dynamo.describe_time_to_live.return_value = {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED", "AttributeName": "expires"}}
    dynamo.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}
    paginator_kwargs = {}
    def get_paginator(operation):
        def paginate(**kwargs):
            if operation == "list_backups":
                paginator_kwargs.update(kwargs)
                return iter([{"BackupSummaries": [{"TableName": "ledger", "BackupName": "daily", "BackupType": "AWS_BACKUP", "BackupCreationDateTime": "2026-01-01", "BackupStatus": "AVAILABLE"}]}])
            return iter([{"TableNames": ["ledger"]}])
        return type("Paginator", (), {"paginate": lambda self, **kwargs: paginate(**kwargs)})()
    dynamo.get_paginator.side_effect = get_paginator
    result = databases.collect_database_data(Session({"rds": paginator_client([]), "dynamodb": dynamo, "docdb": paginator_client([]), "kms": paginator_client([])}))
    table = result["dynamodb_tables"][0]
    assert (table["Status"], table["ItemCount"], table["SizeBytes"], table["Encrypted"]) == ("ACTIVE", 4, 20, True)
    assert table["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]
    assert table["DeletionProtectionEnabled"] is True
    assert table["TTL"]["AttributeName"] == "expires"
    assert table["PITR"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "ENABLED"
    assert table["Backups"][0]["BackupName"] == "daily"
    assert table["Backups"][0]["BackupType"] == "AWS_BACKUP"
    assert paginator_kwargs == {"BackupType": "ALL"}
    assert all(table["Enrichment"][key]["status"] == "complete" for key in ("ttl", "pitr", "backups"))
    assert all(unit.get("impact") == "enrichment" for unit in result["_collection"]["units"] if unit["operation"] in {"describe_time_to_live", "describe_continuous_backups", "list_backups"})


def test_dynamodb_enrichment_access_denied_is_reported():
    dynamo = paginator_client([{"TableNames": ["ledger"]}])
    dynamo.describe_table.return_value = {"Table": {"TableName": "ledger"}}
    dynamo.describe_time_to_live.side_effect = ClientError({"Error": {"Code": "AccessDeniedException"}}, "DescribeTimeToLive")
    dynamo.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {}}
    dynamo.get_paginator.side_effect = lambda operation: type("Paginator", (), {"paginate": lambda self, **kwargs: iter([{"TableNames": ["ledger"]}] if operation == "list_tables" else [{"BackupSummaries": []}])})()
    result = databases.collect_database_data(Session({"rds": paginator_client([]), "dynamodb": dynamo, "docdb": paginator_client([]), "kms": paginator_client([])}))
    ttl = result["dynamodb_tables"][0]["Enrichment"]["ttl"]
    assert ttl["status"] == "failed" and ttl["reason"] == "permission_denied"
    assert any(unit["operation"] == "describe_time_to_live" and unit["impact"] == "enrichment" and unit["status"] == "failed" for unit in result["_collection"]["units"])


def test_new_dynamodb_calls_match_botocore_models():
    client = boto3.client("dynamodb", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(client) as stub:
        stub.add_response("describe_time_to_live", {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}, {"TableName": "ledger"})
        stub.add_response("describe_continuous_backups", {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "DISABLED"}}, {"TableName": "ledger"})
        stub.add_response("list_backups", {"BackupSummaries": [{"TableName": "ledger", "BackupName": "daily", "BackupType": "AWS_BACKUP", "BackupCreationDateTime": __import__("datetime").datetime(2026, 1, 1), "BackupStatus": "AVAILABLE"}]}, {"BackupType": "ALL"})
        client.describe_time_to_live(TableName="ledger")
        client.describe_continuous_backups(TableName="ledger")
        paginator = client.get_paginator("list_backups")
        list(paginator.paginate(BackupType="ALL"))
        stub.assert_no_pending_responses()
