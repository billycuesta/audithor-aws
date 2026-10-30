# collectors/connectivity.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

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
        "nat_gateways": []
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

        except ClientError as e:
            # Gracefully skip regions that are disabled or inaccessible
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] in common_errors:
                continue
        except Exception:
            # Catch any other unexpected error and continue to the next region
            continue
            
    return result

