# collectors/connectivity.py
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from .utils import get_all_aws_regions # Importación relativa
from .diagnostics import classify_error

def _record_region(result, group, region, exc=None):
    entry = {"status": "failed", "reason": classify_error(exc)["category"]} if exc else {"status": "complete"}
    enrichment = result["Enrichment"][group]
    enrichment["regions"][region] = entry
    statuses = [item["status"] for item in enrichment["regions"].values()]
    enrichment["status"] = "failed" if statuses and all(s == "failed" for s in statuses) else "partial" if "failed" in statuses else "complete"
    if exc:
        enrichment["reason"] = entry["reason"]
    else:
        enrichment.pop("reason", None)


def _collect_network_firewalls(session, region, result):
    client = session.client("network-firewall", region_name=region)
    try:
        firewalls = [f for page in client.get_paginator("list_firewalls").paginate() for f in page.get("Firewalls", [])]
        for item in firewalls:
            arn = item.get("FirewallArn")
            detail_response = client.describe_firewall(FirewallArn=arn)
            firewall = detail_response.get("Firewall", {})
            status = detail_response.get("FirewallStatus", {})
            policy_arn = firewall.get("FirewallPolicyArn")
            policy = client.describe_firewall_policy(FirewallPolicyArn=policy_arn).get("FirewallPolicy", {}) if policy_arn else {}
            groups = []
            for ref in policy.get("StatelessRuleGroupReferences", []) + policy.get("StatefulRuleGroupReferences", []):
                group_response = client.describe_rule_group(RuleGroupArn=ref["ResourceArn"])
                group = group_response.get("RuleGroup", {})
                response = group_response.get("RuleGroupResponse", {})
                source = group.get("RulesSource", {})
                summary = source.get("RulesString")
                if summary is not None:
                    summary = summary[:2000]
                elif "RulesSourceList" in source:
                    summary = {k: source["RulesSourceList"].get(k) for k in ("Targets", "TargetTypes", "GeneratedRulesType")}
                elif "StatelessRulesAndCustomActions" in source:
                    summary = {"StatelessRuleCount": len(source["StatelessRulesAndCustomActions"].get("StatelessRules", []))}
                else:
                    summary = {"StatefulRuleCount": len(source.get("StatefulRules", []))}
                groups.append({"RuleGroupName": response.get("RuleGroupName"), "RuleGroupArn": response.get("RuleGroupArn"), "Type": response.get("Type"), "Capacity": response.get("Capacity"), "RulesSummary": summary})
            try:
                logging = client.describe_logging_configuration(FirewallArn=arn).get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])
                logs = [{"LogType": c.get("LogType"), "LogDestinationType": c.get("LogDestinationType"), "LogDestination": c.get("LogDestination")} for c in logging]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {"ResourceNotFoundException", "InvalidRequestException"}:
                    raise
                logs = []
            result["network_firewalls"].append({"Region": region, "FirewallId": firewall.get("FirewallId"), "VpcId": firewall.get("VpcId"), "SubnetMappings": firewall.get("SubnetMappings", []), "EndpointIds": [v["Attachment"]["EndpointId"] for v in status.get("SyncStates", {}).values() if v.get("Attachment", {}).get("EndpointId")], "FirewallPolicyArn": policy_arn, "DeleteProtection": firewall.get("DeleteProtection"), "ChangeProtection": firewall.get("FirewallPolicyChangeProtection"), "SubnetChangeProtection": firewall.get("SubnetChangeProtection"), "DefaultActions": {k: policy.get(k, []) for k in ("StatelessDefaultActions", "StatelessFragmentDefaultActions", "StatefulDefaultActions", "StatefulEngineOptions")}, "RuleGroupReferences": policy.get("StatelessRuleGroupReferences", []) + policy.get("StatefulRuleGroupReferences", []), "RuleGroups": groups, "Logging": logs or "Not configured"})
        _record_region(result, "networkFirewall", region)
    except (ClientError, BotoCoreError) as exc:
        _record_region(result, "networkFirewall", region, exc)


def _collect_transit_gateways(client, region, result):
    try:
        for page in client.get_paginator("describe_transit_gateways").paginate():
            for gateway in page.get("TransitGateways", []):
                options = gateway.get("Options", {})
                result["transit_gateways"].append({"Region": region, "TransitGatewayId": gateway.get("TransitGatewayId"), "OwnerId": gateway.get("OwnerId"), "DefaultRouteTableAssociation": options.get("DefaultRouteTableAssociation"), "DefaultRouteTablePropagation": options.get("DefaultRouteTablePropagation"), "AutoAcceptSharedAttachments": options.get("AutoAcceptSharedAttachments"), "AssociationDefaultRouteTableId": options.get("AssociationDefaultRouteTableId"), "PropagationDefaultRouteTableId": options.get("PropagationDefaultRouteTableId")})
        _record_region(result, "transitGateways", region)
    except (ClientError, BotoCoreError) as exc:
        _record_region(result, "transitGateways", region, exc)


def _collect_tgw_routing(client, region, result):
    try:
        for page in client.get_paginator("describe_transit_gateway_route_tables").paginate():
            for table in page.get("TransitGatewayRouteTables", []):
                table_id = table["TransitGatewayRouteTableId"]
                associations = [a for p in client.get_paginator("get_transit_gateway_route_table_associations").paginate(TransitGatewayRouteTableId=table_id) for a in p.get("Associations", [])]
                propagations = [a for p in client.get_paginator("get_transit_gateway_route_table_propagations").paginate(TransitGatewayRouteTableId=table_id) for a in p.get("TransitGatewayRouteTablePropagations", [])]
                response = client.search_transit_gateway_routes(TransitGatewayRouteTableId=table_id, Filters=[{"Name": "type", "Values": ["static", "propagated"]}])
                result["tgw_route_tables"].append({"Region": region, "TransitGatewayRouteTableId": table_id, "Associations": associations, "Propagations": propagations, "Routes": response.get("Routes", []), "AdditionalRoutesAvailable": response.get("AdditionalRoutesAvailable", False)})
        _record_region(result, "tgwRouting", region)
    except (ClientError, BotoCoreError) as exc:
        _record_region(result, "tgwRouting", region, exc)


def _collect_tgw_shares(session, region, result):
    try:
        client = session.client("ram", region_name=region)
        shares = [s for p in client.get_paginator("get_resource_shares").paginate(resourceOwner="SELF") for s in p.get("resourceShares", [])]
        resources = [r for p in client.get_paginator("list_resources").paginate(resourceOwner="SELF", resourceType="ec2:TransitGateway") for r in p.get("resources", [])]
        share_arns = sorted({r.get("resourceShareArn") for r in resources if r.get("resourceShareArn")})
        if share_arns:
            principals = [p for page in client.get_paginator("list_principals").paginate(resourceOwner="SELF", resourceShareArns=share_arns) for p in page.get("principals", [])]
            for principal in principals:
                result["tgw_shares"].append({"Region": region, "ShareArn": principal.get("resourceShareArn"), "Principal": principal.get("id"), "External": principal.get("external", False)})
        _record_region(result, "tgwShares", region)
    except (ClientError, BotoCoreError) as exc:
        _record_region(result, "tgwShares", region, exc)


def collect_connectivity_data(session):
    """
    Collects data on AWS networking resources across all available regions.

    This function scans each AWS region to gather information on key connectivity
    components: active VPC Peering Connections, available Transit Gateway VPC 
    attachments, available Site-to-Site VPN connections, and all VPC Endpoints.

    Args:
        session (boto3.Session): The Boto3 session object used for AWS 
                                 authentication and to discover all regions.

    Returns:
        dict: A dictionary containing lists of networking resources, structured as:
              {
                  "peering_connections": [...],
                  "tgw_attachments": [...],
                  "vpn_connections": [...],
                  "vpc_endpoints": [...]
              }

    Example:
        >>> import boto3
        >>>
        >>> # This assumes 'get_all_aws_regions' is an available function
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> connectivity_info = collect_connectivity_data(aws_session)
        >>> print(f"Found {len(connectivity_info['vpn_connections'])} active VPNs.")
    """
    regions = get_all_aws_regions(session)
    result = {
        "peering_connections": [],
        "tgw_attachments": [],
        "vpn_connections": [],
        "vpc_endpoints": [],
        "nat_gateways": [],
        "route_tables": [],
        "endpoint_coverage": [],
        "network_firewalls": [], "transit_gateways": [], "tgw_route_tables": [], "tgw_shares": [],
        "Enrichment": {"routeTables": {"status": "complete"}, "endpointCoverage": {"status": "complete"},
                      **{name: {"status": "complete", "regions": {}} for name in ("networkFirewall", "transitGateways", "tgwRouting", "tgwShares")}}
    }

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)

            
            # --- 1. VPC Peering Connections (active only) ---
            peering_paginator = ec2_client.get_paginator('describe_vpc_peering_connections')
            filters = [{'Name': 'status-code', 'Values': ['active']}]
            for page in peering_paginator.paginate(Filters=filters):
                for pcx in page.get("VpcPeeringConnections", []):
                    result["peering_connections"].append({
                        "Region": region,
                        "ConnectionId": pcx.get("VpcPeeringConnectionId"),
                        "RequesterVpc": pcx.get("RequesterVpcInfo", {}),
                        "AccepterVpc": pcx.get("AccepterVpcInfo", {})
                    })

            # --- 2. Transit Gateway VPC Attachments (available only) ---
            tgw_paginator = ec2_client.get_paginator('describe_transit_gateway_attachments')
            filters = [{'Name': 'resource-type', 'Values': ['vpc']}, {'Name': 'state', 'Values': ['available']}]
            for page in tgw_paginator.paginate(Filters=filters):
                for tgw_attachment in page.get("TransitGatewayAttachments", []):
                    result["tgw_attachments"].append({
                        "Region": region,
                        "AttachmentId": tgw_attachment.get("TransitGatewayAttachmentId"),
                        "TransitGatewayId": tgw_attachment.get("TransitGatewayId"),
                        "VpcId": tgw_attachment.get("ResourceId"),
                        "VpcOwnerId": tgw_attachment.get("ResourceOwnerId")
                    })

            # --- 3. Site-to-Site VPN Connections (available only) ---
            filters = [{'Name': 'state', 'Values': ['available']}]
            vpns = ec2_client.describe_vpn_connections(Filters=filters)
            for vpn in vpns.get("VpnConnections", []):
                result["vpn_connections"].append({
                    "Region": region,
                    "VpnConnectionId": vpn.get("VpnConnectionId"),
                    "CustomerGatewayId": vpn.get("CustomerGatewayId"),
                    "TransitGatewayId": vpn.get("TransitGatewayId", "N/A"),
                    "State": vpn.get("State")
                })

            # --- 4. VPC Endpoints ---
            endpoint_paginator = ec2_client.get_paginator('describe_vpc_endpoints')
            for page in endpoint_paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                     result["vpc_endpoints"].append({
                        "Region": region,
                        "VpcEndpointId": endpoint.get("VpcEndpointId"),
                        "VpcId": endpoint.get("VpcId"),
                        "ServiceName": endpoint.get("ServiceName"),
                        "EndpointType": endpoint.get("VpcEndpointType"),
                        "State": endpoint.get("State")
                    })

            # --- 5. NAT Gateways ---                     
            nat_paginator = ec2_client.get_paginator('describe_nat_gateways')
            for page in nat_paginator.paginate():
                for nat_gateway in page.get("NatGateways", []):
                    result["nat_gateways"].append({
                        "Region": region,
                        "NatGatewayId": nat_gateway["NatGatewayId"],
                        "VpcId": nat_gateway["VpcId"],
                        "SubnetId": nat_gateway["SubnetId"],
                        "State": nat_gateway["State"],
                        "ConnectivityType": nat_gateway.get("ConnectivityType", "public"),
                        "NatGatewayAddresses": nat_gateway.get("NatGatewayAddresses", []),
                        "CreateTime": str(nat_gateway.get("CreateTime", "")),
                        "Tags": nat_gateway.get("Tags", [])
                    })

            # --- Route tables and endpoint coverage ---
            tables = []
            try:
                tables = ec2_client.describe_route_tables().get("RouteTables", [])
                for table in tables:
                    result["route_tables"].append({"Region": region, "RouteTableId": table.get("RouteTableId"), "VpcId": table.get("VpcId"), "Routes": table.get("Routes", []), "Associations": table.get("Associations", [])})
            except ClientError as exc:
                reason = classify_error(exc)["category"]
                result["Enrichment"]["routeTables"] = {"status": "failed", "reason": reason}
                result["Enrichment"]["endpointCoverage"] = {"status": "failed", "reason": reason}

            endpoints = [e for e in result["vpc_endpoints"] if e["Region"] == region]
            by_vpc = {}
            for endpoint in endpoints:
                suffix = (endpoint.get("ServiceName") or "").rsplit(".", 1)[-1].lower()
                service = {"s3": "S3", "dynamodb": "DynamoDB", "kms": "KMS"}.get(suffix)
                if service:
                    by_vpc.setdefault(endpoint.get("VpcId"), {})[service] = {"EndpointType": endpoint.get("EndpointType")}
            vpc_ids = {table.get("VpcId") for table in tables if table.get("VpcId")}
            vpc_ids.update(by_vpc)
            for vpc_id in vpc_ids:
                services = by_vpc.get(vpc_id, {})
                result["endpoint_coverage"].append({"Region": region, "VpcId": vpc_id, "Services": {name: services.get(name, "Missing") for name in ("S3", "DynamoDB", "KMS")}})

            _collect_network_firewalls(session, region, result)
            _collect_transit_gateways(ec2_client, region, result)
            _collect_tgw_routing(ec2_client, region, result)
            _collect_tgw_shares(session, region, result)

        except ClientError as e:
            result["Enrichment"]["endpointCoverage"] = {"status": "failed", "reason": classify_error(e)["category"]}
            # Gracefully skip regions that are disabled or inaccessible
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] in common_errors:
                continue
        except BotoCoreError:
            # Continue when an AWS SDK transport or service error prevents regional collection.
            continue
            
    return result

