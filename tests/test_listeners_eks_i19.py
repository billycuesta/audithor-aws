import boto3
import pytest
from botocore.stub import Stubber
from unittest.mock import Mock
from botocore.exceptions import ClientError

from audithor.collectors import compute, exposure


class Session:
    region_name = "us-east-1"
    def __init__(self, clients): self.clients = clients
    def client(self, service, **kwargs):
        if service in self.clients: return self.clients[service]
        client = Mock()
        client.get_paginator.return_value.paginate.return_value = []
        client.list_buckets.return_value = {"Buckets": []}
        client.describe_instances.return_value = {"Reservations": []}
        client.describe_security_groups.return_value = {"SecurityGroups": []}
        client.list_functions.return_value = {"Functions": []}
        client.list_roles.return_value = {"Roles": []}
        return client
    def get_partition_for_region(self, region): return "aws"
    def get_available_regions(self, service, **kwargs): return ["us-east-1"]


def test_public_listener_export_includes_plain_and_tls_fields(monkeypatch):
    client = Mock()
    client.describe_ssl_policies.return_value = {"SslPolicies": [{"Name": "policy", "SslProtocols": ["TLSv1.2"], "Ciphers": [{"Name": "cipher-one"}]}, {"Name": "tls-policy", "SslProtocols": ["TLSv1.3"], "Ciphers": [{"Name": "cipher-two"}]}]}
    client.describe_load_balancers.return_value = {"LoadBalancers": [{"Scheme": "internet-facing", "LoadBalancerArn": "arn:lb", "LoadBalancerName": "public"}]}
    client.describe_listeners.return_value = {"Listeners": [
        {"Port": 80, "Protocol": "HTTP", "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg-http"}]},
        {"Port": 443, "Protocol": "HTTPS", "SslPolicy": "policy", "DefaultActions": [{"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": "arn:tg-https"}]}}]},
        {"Port": 8443, "Protocol": "TLS", "SslPolicy": "tls-policy", "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg-tls"}]},
        {"Port": 53, "Protocol": "UDP", "DefaultActions": [{"Type": "fixed-response"}]}
    ]}
    monkeypatch.setattr(exposure, "get_all_aws_regions", lambda session: ["us-east-1"])
    monkeypatch.setattr(exposure, "collect_network_ports_data", lambda session, regions: [])
    monkeypatch.setattr(exposure, "collect_api_gateway_details", lambda session, region: [])
    result = exposure.collect_exposure_data(Session({"elbv2": client}))
    listeners = result["details"]["ALB/NLB Public"]["us-east-1"][0]["listeners"]
    assert listeners[0] == {"port": 80, "protocol": "HTTP", "defaultActionTypes": ["forward"], "targetGroupArns": ["arn:tg-http"]}
    assert listeners[1]["targetGroupArns"] == ["arn:tg-https"]
    assert listeners[1]["policyName"] == "policy"
    assert listeners[1]["isOutdated"] is False
    assert listeners[1]["tlsVersions"] == ["TLSv1.2"]
    assert listeners[1]["ciphers"] == ["cipher-one"]
    assert listeners[2]["policyName"] == "tls-policy"
    assert listeners[2]["isOutdated"] is False
    assert listeners[2]["tlsVersions"] == ["TLSv1.3"]
    assert listeners[2]["ciphers"] == ["cipher-two"]
    assert "policyName" not in listeners[0]
    assert listeners[3]["defaultActionTypes"] == ["fixed-response"]


def test_compute_eks_endpoint_fields_from_cluster_resources_vpc_config(monkeypatch):
    eks = Mock()
    eks.get_paginator.return_value.paginate.return_value = [{"clusters": ["cluster"]}]
    eks.describe_cluster.return_value = {"cluster": {"arn": "arn:eks", "version": "1.29", "resourcesVpcConfig": {
        "endpointPublicAccess": True, "endpointPrivateAccess": False,
        "publicAccessCidrs": ["0.0.0.0/0"], "securityGroupIds": ["sg-1"], "clusterSecurityGroupId": "sg-2"}}}
    clients = {"sts": Mock(), "ec2": Mock(), "lambda": Mock(), "eks": eks, "ecs": Mock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    clients["ec2"].get_paginator.return_value.paginate.return_value = []
    clients["lambda"].get_paginator.return_value.paginate.return_value = []
    clients["ecs"].get_paginator.return_value.paginate.return_value = []
    monkeypatch.setattr(compute, "get_all_aws_regions", lambda session: ["us-east-1"])
    result = compute.collect_compute_data(Session(clients))
    cluster = result["eks_clusters"][0]
    assert cluster["ClusterName"] == "cluster"
    assert cluster["ARN"] == "arn:eks"
    assert cluster["Version"] == "1.29"
    assert cluster["EndpointPublicAccess"] is True
    assert cluster["EndpointPrivateAccess"] is False
    assert cluster["PublicAccessCidrs"] == ["0.0.0.0/0"]
    assert cluster["SecurityGroupIds"] == ["sg-1"]
    assert cluster["ClusterSecurityGroupId"] == "sg-2"
    assert cluster["Enrichment"]["endpointAccess"]["status"] == "complete"


def test_eks_access_denied_retains_cluster_with_failed_endpoint_enrichment(monkeypatch):
    eks = Mock()
    eks.get_paginator.return_value.paginate.return_value = [{"clusters": ["restricted"]}]
    eks.describe_cluster.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeCluster")
    clients = {"sts": Mock(), "ec2": Mock(), "lambda": Mock(), "eks": eks, "ecs": Mock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    clients["ec2"].get_paginator.return_value.paginate.return_value = []
    clients["lambda"].get_paginator.return_value.paginate.return_value = []
    clients["ecs"].get_paginator.return_value.paginate.return_value = []
    monkeypatch.setattr(compute, "get_all_aws_regions", lambda session: ["us-east-1"])
    result = compute.collect_compute_data(Session(clients))
    cluster = result["eks_clusters"][0]
    assert cluster["ClusterName"] == "restricted"
    assert cluster["EndpointPublicAccess"] is None
    assert cluster["EndpointPrivateAccess"] is None
    assert cluster["PublicAccessCidrs"] is None
    assert cluster["SecurityGroupIds"] is None
    assert cluster["ClusterSecurityGroupId"] is None
    assert cluster["Enrichment"]["endpointAccess"] == {"status": "failed", "reason": "permission_denied"}


def test_eks_describe_cluster_stubber_uses_real_model(monkeypatch):
    eks = boto3.client("eks", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    ec2 = Mock(); ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}
    for svc in ("ec2", "lambda", "ecs"):
        c = Mock(); c.get_paginator.return_value.paginate.return_value = []
        if svc == "ec2": c.describe_regions.return_value = ec2.describe_regions.return_value
        if svc == "ec2": ec2 = c
        elif svc == "lambda": lam = c
        else: ecs = c
    monkeypatch.setattr(compute, "get_all_aws_regions", lambda session: ["us-east-1"])
    sts = Mock(); sts.get_caller_identity.return_value = {"Account": "123456789012"}
    with Stubber(eks) as stub:
        stub.add_response("list_clusters", {"clusters": ["cluster"]})
        stub.add_response("describe_cluster", {"cluster": {"name": "cluster", "arn": "arn:aws:eks:us-east-1:123456789012:cluster/cluster", "version": "1.29", "resourcesVpcConfig": {"subnetIds": ["subnet-1"], "securityGroupIds": ["sg-1"], "clusterSecurityGroupId": "sg-2", "vpcId": "vpc-1", "endpointPublicAccess": True, "endpointPrivateAccess": True, "publicAccessCidrs": ["10.0.0.0/8"]}}})
        result = compute.collect_compute_data(Session({"sts": sts, "ec2": ec2, "lambda": lam, "eks": eks, "ecs": ecs}))
        stub.assert_no_pending_responses()
    assert result["eks_clusters"][0]["ClusterSecurityGroupId"] == "sg-2"
