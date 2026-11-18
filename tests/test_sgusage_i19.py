from types import SimpleNamespace
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

from audithor.collectors import network_policies
from tests.test_collection import Session, error, paginator_client


def test_network_interfaces_and_existing_keys():
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_network_acls.return_value = {"NetworkAcls": []}
    ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "VpcId": "vpc-1", "Description": "web", "Tags": [], "IpPermissions": [], "IpPermissionsEgress": []}]}
    ec2.describe_subnets.return_value = {"Subnets": []}
    pages = {"describe_network_interfaces": [{"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "InterfaceType": "vpc_endpoint", "RequesterId": "123", "RequesterManaged": True, "Description": "endpoint", "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": [{"GroupId": "sg-1"}], "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.1"}], "Association": {"PublicIp": "198.51.100.1"}}]}], "describe_nat_gateways": [{"NatGateways": []}]}
    ec2.get_paginator.side_effect = lambda name: SimpleNamespace(paginate=lambda: iter(pages[name]))
    result = network_policies.collect_network_policies_data(Session({"ec2": ec2}))
    assert result["vpcs"] == [] and result["acls"] == [] and result["subnets"] == [] and result["nat_gateways"] == []
    assert result["network_interfaces"] == [{"Region": "us-east-1", "NetworkInterfaceId": "eni-1", "InterfaceType": "vpc_endpoint", "RequesterId": "123", "RequesterManaged": True, "Description": "endpoint", "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": ["sg-1"], "PrivateIpAddresses": ["10.0.0.1"], "PublicIp": "198.51.100.1"}]
    assert result["Enrichment"]["networkInterfaces"] == {"status": "complete", "regions": {"us-east-1": {"status": "complete"}}}
    assert result["Enrichment"]["securityGroupRules"]["status"] == result["Enrichment"]["networkAcls"]["status"] == "complete"


def test_network_interfaces_access_denied_is_enrichment_failure():
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_network_acls.return_value = {"NetworkAcls": []}
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_subnets.return_value = {"Subnets": []}
    ec2.get_paginator.side_effect = lambda name: SimpleNamespace(paginate=lambda: (_ for _ in ()).throw(error()) if name == "describe_network_interfaces" else iter([]))
    result = network_policies.collect_network_policies_data(Session({"ec2": ec2}))
    assert result["Enrichment"]["networkInterfaces"] == {"status": "failed", "regions": {"us-east-1": {"status": "failed", "reason": "permission_denied"}}}


def test_network_interfaces_botocore_stubber():
    client = boto3.client("ec2", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    ec2 = Mock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_network_acls.return_value = {"NetworkAcls": []}
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_subnets.return_value = {"Subnets": []}
    ec2.get_paginator = client.get_paginator
    session = Session({"ec2": ec2})
    with Stubber(client) as stub:
        stub.add_response("describe_network_interfaces", {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "InterfaceType": "vpc_endpoint", "RequesterId": "123456789012", "RequesterManaged": True, "Description": "endpoint", "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": [{"GroupId": "sg-1"}], "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.1"}], "Association": {"PublicIp": "198.51.100.1"}}]}, {})
        stub.add_response("describe_nat_gateways", {"NatGateways": []}, {})
        result = network_policies.collect_network_policies_data(session)
        stub.assert_no_pending_responses()
    assert result["network_interfaces"][0]["NetworkInterfaceId"] == "eni-1"
    assert result["network_interfaces"][0]["InterfaceType"] == "vpc_endpoint"
    assert result["network_interfaces"][0]["RequesterId"] == "123456789012"
    assert result["network_interfaces"][0]["RequesterManaged"] is True
    assert result["network_interfaces"][0]["Description"] == "endpoint"
    assert result["network_interfaces"][0]["VpcId"] == "vpc-1"
    assert result["network_interfaces"][0]["SubnetId"] == "subnet-1"
    assert result["network_interfaces"][0]["Groups"] == ["sg-1"]
    assert result["network_interfaces"][0]["PrivateIpAddresses"] == ["10.0.0.1"]
    assert result["network_interfaces"][0]["PublicIp"] == "198.51.100.1"
