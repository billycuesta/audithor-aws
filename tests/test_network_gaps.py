from unittest.mock import Mock
import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError
from audithor.collectors.network_policies import collect_network_policies_data
from audithor.collectors.connectivity import collect_connectivity_data

class Session:
    region_name = 'us-east-1'
    def __init__(self, clients): self.clients = clients
    def client(self, service, **kwargs): return self.clients[service]

def ec2_mock():
    c = Mock()
    c.describe_regions.return_value = {'Regions': [{'RegionName':'us-east-1'}]}
    c.describe_vpcs.return_value = {'Vpcs': [{'VpcId':'vpc-1','CidrBlock':'10.0.0.0/16','IsDefault':False,'Tags':[]}]}
    c.describe_network_acls.return_value = {'NetworkAcls':[{'NetworkAclId':'acl-1','VpcId':'vpc-1','Entries':[{'RuleNumber':100,'Egress':False,'Protocol':'6','RuleAction':'allow','CidrBlock':'0.0.0.0/0','PortRange':{'From':443,'To':443}}],'Associations':[{'SubnetId':'subnet-1'}]}]}
    c.describe_security_groups.return_value = {'SecurityGroups':[{'GroupId':'sg-1','GroupName':'web','VpcId':'vpc-1','Description':'web','IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'0.0.0.0/0','Description':'<img src=x onerror=alert(1)>'}],'Ipv6Ranges':[{'CidrIpv6':'::/0'}],'UserIdGroupPairs':[{'GroupId':'sg-peer','UserId':'123456789012'}],'PrefixListIds':[{'PrefixListId':'pl-1'}]}],'IpPermissionsEgress':[{'IpProtocol':'udp','FromPort':53,'ToPort':53,'IpRanges':[{'CidrIp':'10.0.0.0/8'}]}]} ]}
    c.describe_subnets.return_value = {'Subnets':[]}
    c.get_paginator.return_value.paginate.return_value = []
    return c

def test_network_enrichments_and_old_keys():
    c=ec2_mock()
    result=collect_network_policies_data(Session({'ec2':c}))
    assert set(('vpcs','acls','security_groups','subnets','all_regions','nat_gateways')) <= result.keys()
    sg=result['security_groups'][0]
    assert sg['IngressRules'][0]['IpProtocol']=='tcp'
    assert sg['IngressRules'][0]['FromPort']==443
    assert sg['IngressRules'][0]['ToPort']==443
    assert sg['IngressRules'][0]['IpRanges'][0]['CidrIp']=='0.0.0.0/0'
    assert sg['IngressRules'][0]['IpRanges'][0]['Description']=='<img src=x onerror=alert(1)>'
    assert sg['IngressRules'][0]['Ipv6Ranges'][0]['CidrIpv6']=='::/0'
    assert sg['IngressRules'][0]['UserIdGroupPairs'][0]['UserId']=='123456789012'
    assert sg['IngressRules'][0]['UserIdGroupPairs'][0]['GroupId']=='sg-peer'
    assert sg['IngressRules'][0]['PrefixListIds'][0]['PrefixListId']=='pl-1'
    assert sg['EgressRules'][0]['IpProtocol']=='udp'
    assert sg['EgressRules'][0]['FromPort']==53
    assert sg['EgressRules'][0]['ToPort']==53
    assert sg['EgressRules'][0]['IpRanges'][0]['CidrIp']=='10.0.0.0/8'
    assert result['acls'][0]['Entries'][0]['RuleNumber']==100
    assert result['acls'][0]['Entries'][0]['Egress'] is False
    assert result['acls'][0]['Entries'][0]['Protocol']=='6'
    assert result['acls'][0]['Entries'][0]['RuleAction']=='allow'
    assert result['acls'][0]['Entries'][0]['CidrBlock']=='0.0.0.0/0'
    assert result['acls'][0]['Entries'][0]['PortRange']['From']==443
    assert result['acls'][0]['Entries'][0]['PortRange']['To']==443
    assert result['acls'][0]['SubnetAssociations'][0]['SubnetId']=='subnet-1'
    assert sg['Enrichment']['securityGroupRules']['status']=='complete'
    assert result['acls'][0]['Enrichment']['networkAcls']['status']=='complete'

def test_network_access_denied_is_reported():
    c=ec2_mock(); c.describe_security_groups.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'DescribeSecurityGroups')
    result=collect_network_policies_data(Session({'ec2':c}))
    assert result['Enrichment']['securityGroupRules']=={'status':'failed','reason':'permission_denied'}

def test_route_table_and_endpoint_coverage_stubbed():
    client=boto3.client('ec2',region_name='us-east-1',aws_access_key_id='testing',aws_secret_access_key='testing')
    with Stubber(client) as stub:
        stub.add_response('describe_regions', {'Regions':[{'RegionName':'us-east-1','Endpoint':'ec2.us-east-1.amazonaws.com'}]}, {})
        stub.add_response('describe_vpc_peering_connections',{'VpcPeeringConnections':[]}, {'Filters':[{'Name':'status-code','Values':['active']}]})
        stub.add_response('describe_transit_gateway_attachments',{'TransitGatewayAttachments':[]}, {'Filters':[{'Name':'resource-type','Values':['vpc']},{'Name':'state','Values':['available']}]})
        stub.add_response('describe_vpn_connections',{'VpnConnections':[]}, {'Filters':[{'Name':'state','Values':['available']}]})
        stub.add_response('describe_vpc_endpoints',{'VpcEndpoints':[{'VpcEndpointId':'vpce-1','VpcId':'vpc-1','ServiceName':'com.amazonaws.us-east-1.s3','VpcEndpointType':'Gateway','State':'available'},{'VpcEndpointId':'vpce-2','VpcId':'vpc-1','ServiceName':'com.amazonaws.us-east-1.dynamodb','VpcEndpointType':'Gateway','State':'available'},{'VpcEndpointId':'vpce-3','VpcId':'vpc-1','ServiceName':'com.amazonaws.us-east-1.kms','VpcEndpointType':'Interface','State':'available'}]}, {})
        stub.add_response('describe_nat_gateways',{'NatGateways':[]}, {})
        stub.add_response('describe_route_tables',{'RouteTables':[{'RouteTableId':'rtb-1','VpcId':'vpc-1','Routes':[{'DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-1'}],'Associations':[{'Main':True}]},{'RouteTableId':'rtb-2','VpcId':'vpc-2','Routes':[],'Associations':[{'Main':True}]}]}, {})
        result=collect_connectivity_data(Session({'ec2':client}))
        stub.assert_no_pending_responses()
    assert result['route_tables'][0]['Routes'][0]['GatewayId']=='igw-1'
    assert result['route_tables'][0]['Associations'][0]['Main'] is True
    coverage=next(v for v in result['endpoint_coverage'] if v['VpcId']=='vpc-1')
    assert coverage['Services']['S3']['EndpointType']=='Gateway'
    assert coverage['Services']['DynamoDB']['EndpointType']=='Gateway'
    assert coverage['Services']['KMS']['EndpointType']=='Interface'
    missing=next(v for v in result['endpoint_coverage'] if v['VpcId']=='vpc-2')
    assert missing['Services']=={'S3':'Missing','DynamoDB':'Missing','KMS':'Missing'}
    assert result['Enrichment']['routeTables']['status']=='complete'
    assert result['Enrichment']['endpointCoverage']['status']=='complete'

def test_connectivity_access_denied_reports_enrichment():
    c=ec2_mock(); c.get_paginator.return_value.paginate.return_value=[]
    c.describe_vpc_peering_connections.return_value={'VpcPeeringConnections':[]}
    c.describe_transit_gateway_attachments.return_value={'TransitGatewayAttachments':[]}
    c.describe_vpn_connections.return_value={'VpnConnections':[]}
    c.describe_vpc_endpoints.return_value={'VpcEndpoints':[]}; c.describe_nat_gateways.return_value={'NatGateways':[]}
    c.describe_route_tables.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'DescribeRouteTables')
    result=collect_connectivity_data(Session({'ec2':c}))
    assert result['Enrichment']['routeTables']=={'status':'failed','reason':'permission_denied'}
    assert result['Enrichment']['endpointCoverage']=={'status':'failed','reason':'permission_denied'}
    assert 'vpc_endpoints' in result and 'nat_gateways' in result and 'route_tables' in result
