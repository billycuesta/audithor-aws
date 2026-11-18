"""Collect AWS Organizations service control policy region guardrails."""
import json

from .diagnostics import AWS_ERRORS, classify_error


def _values(value):
    return value if isinstance(value, list) else [value] if isinstance(value, str) else []


def collect_region_guardrails(session):
    """Return region-restricting SCPs and their Organizations targets."""
    result = {"Enrichment": {"regionGuardrails": {"status": "complete"}}}
    client = session.client("organizations", region_name="us-east-1")
    try:
        organization = client.describe_organization()["Organization"]
        policies = []
        for page in client.get_paginator("list_policies").paginate(Filter="SERVICE_CONTROL_POLICY"):
            for summary in page.get("Policies", []):
                policy = client.describe_policy(PolicyId=summary["Id"])["Policy"]
                content = json.loads(policy["Content"])
                statements = content.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                accepted = []
                for statement in statements:
                    if statement.get("Effect") != "Deny":
                        continue
                    condition = statement.get("Condition", {})
                    for operator, entries in condition.items():
                        if operator not in {"StringNotEquals", "StringNotLike", "StringEquals", "StringLike"}:
                            continue
                        if "aws:RequestedRegion" not in entries:
                            continue
                        accepted.append((operator, _values(entries["aws:RequestedRegion"]), statement))
                if not accepted:
                    continue
                allowed, denied, exempt = [], [], []
                for operator, regions, statement in accepted:
                    target_regions = allowed if operator in {"StringNotEquals", "StringNotLike"} else denied
                    target_regions.extend(regions)
                    if isinstance(statement.get("NotAction"), list):
                        exempt.extend(statement["NotAction"])
                targets = []
                for page_targets in client.get_paginator("list_targets_for_policy").paginate(PolicyId=summary["Id"]):
                    targets.extend({key: target[key] for key in ("TargetId", "Name", "Type") if key in target}
                                   for target in page_targets.get("Targets", []))
                policies.append({"PolicyId": summary["Id"], "Name": summary.get("Name", policy.get("PolicySummary", {}).get("Name", "")),
                                 "AllowedRegions": list(dict.fromkeys(allowed)), "DeniedRegions": list(dict.fromkeys(denied)),
                                 "ExemptActions": list(dict.fromkeys(exempt)), "Targets": targets})
        result.update({"OrganizationId": organization.get("Id"), "MasterAccountId": organization.get("MasterAccountId"), "Policies": policies})
    except AWS_ERRORS as exc:
        code = classify_error(exc)["category"]
        if getattr(exc, "response", {}).get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException":
            result["Enrichment"]["regionGuardrails"] = {"status": "skipped", "reason": "organizations_not_in_use"}
        else:
            result["Enrichment"]["regionGuardrails"] = {"status": "failed", "reason": code}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        result["Enrichment"]["regionGuardrails"] = {"status": "failed", "reason": "aws_error"}
    return result
