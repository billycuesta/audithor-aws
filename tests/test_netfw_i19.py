import boto3
from botocore.stub import Stubber
from unittest.mock import Mock
from audithor.collectors.connectivity import collect_connectivity_data
from tests.test_collection import Session, error


def paginator_client(pages):
    client = Mock()
    client.paginate.return_value = pages
    return client


def empty_ram():
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = []
    return client


def test_connectivity_enrichment_and_existing_keys():
    fw = Mock()
    fw.get_paginator.side_effect = lambda op: paginator_client([{"Firewalls": []}] if op == "list_firewalls" else [{"TransitGateways": []}] if op == "describe_firewalls" else [{"TransitGatewayRouteTables": []}])
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    ec2.describe_transit_gateways.return_value = {"TransitGateways": []}
    ec2.get_paginator.side_effect = lambda op: paginator_client([{"TransitGatewayRouteTables": []}] if op == "describe_transit_gateway_route_tables" else [{"TransitGatewayAttachments": []}] if op == "describe_transit_gateway_attachments" else [{"VpcPeeringConnections": []}] if op == "describe_vpc_peering_connections" else [{"VpcEndpoints": []}] if op == "describe_vpc_endpoints" else [{"NatGateways": []}])
    ec2.describe_vpn_connections.return_value = {"VpnConnections": []}
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    ram = empty_ram()
    result = collect_connectivity_data(Session({"ec2": ec2, "network-firewall": fw, "ram": ram}))
    assert all(key in result for key in ("peering_connections", "tgw_attachments", "vpn_connections", "vpc_endpoints", "route_tables", "endpoint_coverage"))
    for group in ("networkFirewall", "transitGateways", "tgwRouting", "tgwShares"):
        assert result["Enrichment"][group]["status"] in {"complete", "failed", "skipped"}


def test_firewall_access_denied_enrichment():
    fw = Mock()
    fw.get_paginator.side_effect = error()
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}
    ec2.get_paginator.return_value.paginate.return_value = []
    ec2.describe_vpn_connections.return_value = {"VpnConnections": []}
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    result = collect_connectivity_data(Session({"network-firewall": fw, "ec2": ec2, "ram": empty_ram()}))
    assert result["Enrichment"]["networkFirewall"]["status"] == "failed"
    assert result["Enrichment"]["networkFirewall"]["reason"] == "permission_denied"
    assert result["Enrichment"]["networkFirewall"]["regions"]["us-east-1"]["status"] == "failed"


def test_tgw_and_ram_stubber_uses_real_models_through_collector():
    ec2 = boto3.client("ec2", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    ram = boto3.client("ram", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    ec2_stub, ram_stub = Stubber(ec2), Stubber(ram)
    table_id = "tgw-rtb-1234567890abcdef0"
    share_arn = "arn:aws:ram:us-east-1:123456789012:resource-share/share"
    resource_arn = "arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-1234567890abcdef0"
    ec2_stub.add_response("describe_regions", {"Regions": [{"RegionName": "us-east-1", "Endpoint": "ec2.us-east-1.amazonaws.com"}]}, {})
    ec2_stub.add_response("describe_vpc_peering_connections", {"VpcPeeringConnections": []}, {"Filters": [{"Name": "status-code", "Values": ["active"]}]})
    ec2_stub.add_response("describe_transit_gateway_attachments", {"TransitGatewayAttachments": []}, {"Filters": [{"Name": "resource-type", "Values": ["vpc"]}, {"Name": "state", "Values": ["available"]}]})
    ec2_stub.add_response("describe_vpn_connections", {"VpnConnections": []}, {"Filters": [{"Name": "state", "Values": ["available"]}]})
    ec2_stub.add_response("describe_vpc_endpoints", {"VpcEndpoints": []}, {})
    ec2_stub.add_response("describe_nat_gateways", {"NatGateways": []}, {})
    ec2_stub.add_response("describe_route_tables", {"RouteTables": []}, {})
    ec2_stub.add_response("describe_transit_gateways", {"TransitGateways": []}, {})
    ec2_stub.add_response("describe_transit_gateway_route_tables", {"TransitGatewayRouteTables": [{"TransitGatewayRouteTableId": table_id}]}, {})
    ec2_stub.add_response("get_transit_gateway_route_table_associations", {"Associations": []}, {"TransitGatewayRouteTableId": table_id})
    ec2_stub.add_response("get_transit_gateway_route_table_propagations", {"TransitGatewayRouteTablePropagations": []}, {"TransitGatewayRouteTableId": table_id})
    ec2_stub.add_response("search_transit_gateway_routes", {"Routes": [], "AdditionalRoutesAvailable": False}, {"TransitGatewayRouteTableId": table_id, "Filters": [{"Name": "type", "Values": ["static", "propagated"]}]})
    ram_stub.add_response("get_resource_shares", {"resourceShares": [{"resourceShareArn": share_arn}]}, {"resourceOwner": "SELF"})
    ram_stub.add_response("list_resources", {"resources": [{"arn": resource_arn, "type": "ec2:TransitGateway", "resourceShareArn": share_arn}]}, {"resourceOwner": "SELF", "resourceType": "ec2:TransitGateway"})
    ram_stub.add_response("list_principals", {"principals": [{"id": "123456789012", "resourceShareArn": share_arn, "external": True}]}, {"resourceOwner": "SELF", "resourceShareArns": [share_arn]})
    fw = Mock()
    fw.get_paginator.return_value.paginate.return_value = []
    with ec2_stub, ram_stub:
        result = collect_connectivity_data(Session({"ec2": ec2, "ram": ram, "network-firewall": fw}))
        ec2_stub.assert_no_pending_responses()
        ram_stub.assert_no_pending_responses()
    assert result["tgw_route_tables"][0]["TransitGatewayRouteTableId"] == table_id
    assert result["tgw_route_tables"][0]["AdditionalRoutesAvailable"] is False
    assert result["tgw_shares"] == [{"Region": "us-east-1", "ShareArn": share_arn, "Principal": "123456789012", "External": True}]


def test_network_firewall_stubber_uses_real_model_through_collector():
    client = boto3.client("network-firewall", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    stub = Stubber(client)
    firewall_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall/fw"
    policy_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/policy"
    group_arn = "arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/rules"
    rules_string = "pass tcp any any -> any any (sid:1;)\\n" * 200
    stub.add_response("list_firewalls", {"Firewalls": [{"FirewallArn": firewall_arn, "FirewallName": "fw"}]}, {})
    stub.add_response("describe_firewall", {"Firewall": {"FirewallArn": firewall_arn, "FirewallName": "fw", "FirewallId": "12345678-1234-1234-1234-123456789012", "VpcId": "vpc-1", "FirewallPolicyArn": policy_arn, "SubnetMappings": [{"SubnetId": "subnet-1"}], "DeleteProtection": True, "FirewallPolicyChangeProtection": True, "SubnetChangeProtection": False}, "FirewallStatus": {"Status": "READY", "ConfigurationSyncStateSummary": "IN_SYNC", "SyncStates": {"us-east-1a": {"Attachment": {"EndpointId": "vpce-1"}}}}}, {"FirewallArn": firewall_arn})
    stub.add_response("describe_firewall_policy", {"UpdateToken": "token", "FirewallPolicyResponse": {"FirewallPolicyName": "policy", "FirewallPolicyArn": policy_arn, "FirewallPolicyId": "12345678-1234-1234-1234-123456789012"}, "FirewallPolicy": {"StatelessDefaultActions": ["aws:drop"], "StatelessFragmentDefaultActions": ["aws:drop"], "StatefulDefaultActions": ["aws:drop_strict"], "StatefulEngineOptions": {"RuleOrder": "STRICT_ORDER"}, "StatefulRuleGroupReferences": [{"ResourceArn": group_arn}]}}, {"FirewallPolicyArn": policy_arn})
    stub.add_response("describe_rule_group", {"UpdateToken": "token", "RuleGroup": {"RulesSource": {"RulesString": rules_string}}, "RuleGroupResponse": {"RuleGroupArn": group_arn, "RuleGroupName": "rules", "RuleGroupId": "12345678-1234-1234-1234-123456789012", "Type": "STATEFUL", "Capacity": 100}}, {"RuleGroupArn": group_arn})
    stub.add_response("describe_logging_configuration", {"FirewallArn": firewall_arn, "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "ALERT", "LogDestinationType": "CloudWatchLogs", "LogDestination": {"logGroup": "firewall-logs"}}]}}, {"FirewallArn": firewall_arn})
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    ec2.get_paginator.return_value.paginate.return_value = []
    ec2.describe_vpn_connections.return_value = {"VpnConnections": []}
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    with stub:
        result = collect_connectivity_data(Session({"network-firewall": client, "ec2": ec2, "ram": empty_ram()}))
        stub.assert_no_pending_responses()
    assert result["Enrichment"]["networkFirewall"]["status"] == "complete"
    firewall = result["network_firewalls"][0]
    assert firewall["VpcId"] == "vpc-1"
    assert firewall["SubnetMappings"] == [{"SubnetId": "subnet-1"}]
    assert firewall["EndpointIds"] == ["vpce-1"]
    assert firewall["FirewallPolicyArn"] == policy_arn
    assert firewall["DeleteProtection"] is True
    assert firewall["ChangeProtection"] is True
    assert firewall["SubnetChangeProtection"] is False
    assert firewall["DefaultActions"]["StatelessDefaultActions"] == ["aws:drop"]
    assert firewall["DefaultActions"]["StatefulEngineOptions"] == {"RuleOrder": "STRICT_ORDER"}
    assert firewall["RuleGroups"] == [{"RuleGroupName": "rules", "RuleGroupArn": group_arn, "Type": "STATEFUL", "Capacity": 100, "RulesSummary": rules_string[:2000]}]
    assert len(firewall["RuleGroups"][0]["RulesSummary"]) == 2000
    assert firewall["Logging"] == [{"LogType": "ALERT", "LogDestinationType": "CloudWatchLogs", "LogDestination": {"logGroup": "firewall-logs"}}]
