"""Inspector inventory: service activation, findings and enrichment are distinct."""
from collections import defaultdict
from botocore.exceptions import ClientError
from .diagnostics import Collection, AWS_CONFIG

# Conservative batch size for instance detail requests.
INSTANCE_DETAIL_BATCH_SIZE = 100


def _account_status(client, account_id, diagnostics, region):
    response = client.batch_get_account_status(accountIds=[account_id])
    for failed in response.get("failedAccounts", []):
        diagnostics.failure(ClientError({"Error": {"Code": failed.get("errorCode", "UnknownError")},
                                         "ResponseMetadata": response.get("ResponseMetadata", {})},
                                        "BatchGetAccountStatus"),
                            "inspector2", region, "batch_get_account_status",
                            resourceId=failed.get("accountId"))
    account = next((a for a in response.get("accounts", []) if a.get("accountId") == account_id), None)
    if account is None and not response.get("failedAccounts"):
        diagnostics.record("inspector2", region, "batch_get_account_status", "failed",
                           category="invalid_response")
    return account


def _identity(session):
    return getattr(session, "_audithor_account_id", None) or session.client("sts", config=AWS_CONFIG).get_caller_identity()["Account"]


def collect_inspector_status(session):
    diagnostics = Collection("inspector_status", session)
    account_id = _identity(session)
    statuses = []
    for region in diagnostics.regions(session, "inspector2"):
        with diagnostics.operation("inspector2", region, "batch_get_account_status"):
            client = session.client("inspector2", region_name=region, config=AWS_CONFIG)
            account = _account_status(client, account_id, diagnostics, region)
            if account is None:
                continue
            resource_state = account.get("resourceState", {})
            statuses.append({"Region": region,
                             "InspectorStatus": account.get("state", {}).get("status", "UNKNOWN"),
                             "ScanEC2": resource_state.get("ec2", {}).get("status", "UNKNOWN"),
                             "ScanECR": resource_state.get("ecr", {}).get("status", "UNKNOWN"),
                             "ScanLambda": resource_state.get("lambda", {}).get("status", "NOT_AVAILABLE")})
    return diagnostics.finish({"scan_status": statuses, "findings": [], "findingsStatus": "not_run"})


def collect_inspector_findings(session):
    diagnostics = Collection("inspector_findings", session)
    account_id = _identity(session)
    findings = []
    for region in diagnostics.regions(session, "inspector2"):
        with diagnostics.operation("inspector2", region, "collect_findings"):
            client = session.client("inspector2", region_name=region, config=AWS_CONFIG)
            account = _account_status(client, account_id, diagnostics, region)
            if account is None:
                continue
            status = account.get("state", {}).get("status", "UNKNOWN")
            if status != "ENABLED":
                if status == "DISABLED":
                    diagnostics.record("inspector2", region, "list_findings", "skipped", category="service_disabled")
                else:
                    diagnostics.record("inspector2", region, "list_findings", "failed", category="service_not_ready", serviceStatus=status)
                continue
            for page in client.get_paginator("list_findings").paginate(
                    filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]}):
                findings.extend(dict(f, Region=region) for f in page.get("findings", []))

    instances = defaultdict(set)
    for finding in findings:
        for resource in finding.get("resources", []):
            if resource.get("type") == "AWS_EC2_INSTANCE":
                instances[finding["Region"]].add(resource["id"])
    names = {}
    for region, ids in instances.items():
        with diagnostics.operation("ec2", region, "describe_instances", impact="enrichment"):
            ec2_client = session.client("ec2", region_name=region, config=AWS_CONFIG)
            instance_ids = sorted(ids)
            for start in range(0, len(instance_ids), INSTANCE_DETAIL_BATCH_SIZE):
                for page in ec2_client.get_paginator("describe_instances").paginate(InstanceIds=instance_ids[start:start + INSTANCE_DETAIL_BATCH_SIZE]):
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            names[(region, instance["InstanceId"])] = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), "")
    for finding in findings:
        resources = finding.get("resources", [])
        if resources and resources[0].get("type") == "AWS_EC2_INSTANCE":
            key = finding["Region"], resources[0]["id"]
            finding["resourceName"] = names.get(key, "")
            finding["resourceNameStatus"] = "complete" if key in names else "unknown"
    order = {severity: i for i, severity in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED"])}
    findings.sort(key=lambda f: order.get(f.get("severity"), 99))
    result = diagnostics.finish({"findings": findings})
    result["findingsStatus"] = result["_collection"]["status"]
    return result
