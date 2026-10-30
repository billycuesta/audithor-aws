# collectors/network_policies.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


PROTOCOLS = {'-1': 'ALL', '6': 'TCP', '17': 'UDP', '1': 'ICMP'}


def collect_network_policies_data(session):
    """
    Collects data on VPCs, NACLs, Security Groups, and Subnets from all AWS regions.

    This function iterates through all available AWS regions, queries the EC2
    endpoint for networking components, and aggregates them into lists.

    Args:
        session (boto3.Session): The boto3 session for creating AWS clients.

    Returns:
        dict: A dictionary containing lists of vpcs, acls, security_groups,
              subnets, and all regions that were scanned.

    Example:
        >>> network_data = collect_network_policies_data(boto3.Session())
        >>> print(network_data['vpcs'][0]['VpcId'])
        'vpc-12345678'
    """
    regions = get_all_aws_regions(session)
    result_vpcs, result_acls, result_sgs, result_subnets, result_nat_gateways = [], [], [], [], []

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)

            # Collect VPCs
            for vpc in ec2_client.describe_vpcs().get("Vpcs", []):
                tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                result_vpcs.append({"Region": region, "VpcId": vpc.get("VpcId"), "CidrBlock": vpc.get("CidrBlock"), "IsDefault": vpc.get("IsDefault"), "Tags": tags})

            # Collect Network ACLs
            for acl in ec2_client.describe_network_acls().get("NetworkAcls", []):
                tags = {tag['Key']: tag['Value'] for tag in acl.get('Tags', [])}
                result_acls.append({"Region": region, "AclId": acl.get("NetworkAclId"), "VpcId": acl.get("VpcId"), "IsDefault": acl.get("IsDefault"), "Tags": tags})

            # Collect Security Groups
            for sg in ec2_client.describe_security_groups().get("SecurityGroups", []):
                tags = {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                result_sgs.append({"Region": region, "GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName"), "VpcId": sg.get("VpcId"), "Description": sg.get("Description"), "Tags": tags})

            # Collect Subnets
            for subnet in ec2_client.describe_subnets().get("Subnets", []):
                tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                result_subnets.append({"Region": region, "SubnetId": subnet.get("SubnetId"), "VpcId": subnet.get("VpcId"), "CidrBlock": subnet.get("CidrBlock"), "AvailabilityZone": subnet.get("AvailabilityZone"), "Tags": tags})

            # Collect NAT Gateways
            nat_paginator = ec2_client.get_paginator('describe_nat_gateways')
            for page in nat_paginator.paginate():
                for nat_gw in page.get("NatGateways", []):
                    if nat_gw.get("State") == "available":
                        tags = {tag['Key']: tag['Value'] for tag in nat_gw.get('Tags', [])}
                        result_nat_gateways.append({
                            "Region": region,
                            "NatGatewayId": nat_gw.get("NatGatewayId"),
                            "VpcId": nat_gw.get("VpcId"),
                            "SubnetId": nat_gw.get("SubnetId"),
                            "ConnectivityType": nat_gw.get("ConnectivityType", "public"),
                            "Tags": tags
                        })
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue

    return {
        "vpcs": result_vpcs,
        "acls": result_acls,
        "security_groups": result_sgs,
        "subnets": result_subnets,
        "all_regions": regions,
        "nat_gateways": result_nat_gateways
    }


def _format_to_table(headers, rows, title):
    """
    Utility function to create a formatted text table with borders.

    Args:
        headers (list): A list of strings for the table headers.
        rows (list): A list of lists, where each inner list is a row.
        title (str): The title to be displayed above the table.

    Returns:
        str: A formatted string representing the complete table.
    """
    if not rows:
        return f"\n{title}\nNo rules or entries found."

    col_widths = {header: len(header) for header in headers}
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[headers[i]] = max(col_widths[headers[i]], len(str(cell)))

    header_line = " | ".join(header.ljust(col_widths[header]) for header in headers)
    separator = "-+-".join("-" * col_widths[header] for header in headers)
    body_lines = "\n".join(" | ".join(str(cell).ljust(col_widths[headers[i]]) for i, cell in enumerate(row)) for row in rows)

    return (f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n"
            f"| {title.center(len(header_line))} |\n"
            f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n"
            f"| {header_line} |\n"
            f"+={separator}=+\n"
            f"| " + body_lines.replace("\n", " |\n| ") + " |\n"
            f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+")


def _format_sg_details(sg_details):
    """Internal helper to format Security Group rules into a table."""
    sg = sg_details['SecurityGroups'][0]
    title = f"Security Group Details: {sg['GroupId']} ({sg['GroupName']})"
    headers = ['Direction', 'Protocol', 'Port Range', 'Source/Destination', 'Description']
    rows = []

    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Ingress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Ingress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])

    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Egress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Egress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])

    return _format_to_table(headers, rows, title)


def _format_nacl_details(nacl_details):
    """Internal helper to format Network ACL rules into a table."""
    nacl = nacl_details['NetworkAcls'][0]
    title = f"Network ACL Details: {nacl['NetworkAclId']}"
    headers = ['Rule #', 'Direction', 'Action', 'Protocol', 'Port Range', 'CIDR']
    rows = []

    for entry in sorted(nacl['Entries'], key=lambda x: x['RuleNumber']):
        direction = 'Egress' if entry.get('Egress') else 'Ingress'
        action = entry.get('RuleAction', 'N/A').upper()
        proto = PROTOCOLS.get(str(entry.get('Protocol', '-1')), entry.get('Protocol', 'N/A'))
        port = f"{entry.get('PortRange', {}).get('From', 'All')}-{entry.get('PortRange', {}).get('To', 'All')}".replace('-1-All', 'All')
        cidr = entry.get('CidrBlock', '-')
        rows.append([entry.get('RuleNumber'), direction, action, proto, port, cidr])

    return _format_to_table(headers, rows, title)


def get_network_details_table(session, resource_id, region):
    """
    Gets rules for a Security Group or NACL and returns a formatted text table.

    This function identifies the resource type by its ID prefix (sg- or acl-)
    and fetches the corresponding details to generate a human-readable table.

    Args:
        session (boto3.Session): The boto3 session for creating AWS clients.
        resource_id (str): The ID of the Security Group or Network ACL.
        region (str): The AWS region where the resource exists.

    Returns:
        str: A formatted string table of the rules, or an error message.

    Example:
        >>> table = get_network_details_table(session, 'sg-12345', 'us-east-1')
        >>> print(table)
    """
    resource_id = resource_id.strip()

    try:
        ec2_client = session.client("ec2", region_name=region)

        if resource_id.startswith("sg-"):
            response = ec2_client.describe_security_groups(GroupIds=[resource_id])
            return _format_sg_details(response)

        elif resource_id.startswith("acl-"):
            response = ec2_client.describe_network_acls(NetworkAclIds=[resource_id])
            return _format_nacl_details(response)

        else:
            return "Error: ID must start with 'sg-' (Security Group) or 'acl-' (Network ACL)."

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if "NotFound" in error_code:
            return f"Error: Resource with ID '{resource_id}' not found in region '{region}'."
        return f"An AWS error occurred: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"