import ipaddress
import socket
from collections import defaultdict

import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions  # Relative import

# --- Module Constants ---
PROTOCOLS = {'-1': 'ALL', '6': 'TCP', '17': 'UDP', '1': 'ICMP'}


def _format_to_table(headers, rows, title):
    """
    Utility function to create a formatted text table.

    Args:
        headers (list): A list of strings for the table headers.
        rows (list): A list of lists, where each inner list is a row.
        title (str): The title to be displayed above the table.

    Returns:
        str: A formatted string representing the complete table.
    """
    if not rows:
        return f"{title}\nNo rules or entries found."

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


def pg_format_sg_rules(ec2_client, sg_id):
    """
    Fetches and formats the rules of a Security Group into a text table.

    Args:
        ec2_client (boto3.client): The EC2 client to use for API calls.
        sg_id (str): The ID of the Security Group to format.

    Returns:
        str: A formatted string containing the table of rules.

    Example:
        >>> table = pg_format_sg_rules(ec2_client, 'sg-12345678')
        >>> print(table)
    """
    sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
    rows = []
    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        port_range = f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}" if 'FromPort' in rule else 'ALL'
        sources = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                  [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])]
        for source in (sources or ['-']):
            rows.append(['Ingress', proto, port_range, source or 'N/A'])

    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        port_range = f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}" if 'FromPort' in rule else 'ALL'
        dests = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])]
        for dest in (dests or ['-']):
            rows.append(['Egress', proto, port_range, dest or 'N/A'])

    return _format_to_table(['Direction', 'Protocol', 'Port Range', 'Source/Destination'], rows, f"Details for Security Group: {sg_id}")


def pg_format_nacl_rules(ec2_client, nacl_id):
    """
    Fetches and formats the rules of a Network ACL into a text table.

    Args:
        ec2_client (boto3.client): The EC2 client to use for API calls.
        nacl_id (str): The ID of the Network ACL to format.

    Returns:
        str: A formatted string containing the table of rules.

    Example:
        >>> table = pg_format_nacl_rules(ec2_client, 'acl-12345678')
        >>> print(table)
    """
    nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]
    rows = []
    for entry in sorted(nacl['Entries'], key=lambda x: x['RuleNumber']):
        direction = 'Egress' if entry['Egress'] else 'Ingress'
        proto = PROTOCOLS.get(str(entry['Protocol']), str(entry['Protocol']))
        port_range = f"{entry['PortRange']['From']}-{entry['PortRange']['To']}" if 'PortRange' in entry else 'ALL'
        cidr = entry.get('CidrBlock') or entry.get('Ipv6CidrBlock', '-')
        rows.append([entry['RuleNumber'], direction, entry['RuleAction'].upper(), proto, port_range, cidr])

    return _format_to_table(['Rule #', 'Direction', 'Action', 'Protocol', 'Port Range', 'CIDR'], rows, f"Details for Network ACL: {nacl_id}")


def pg_format_route_table(ec2_client, rtb_id):
    """
    Fetches and formats the routes of a Route Table into a text table.
    (Esta versión es compatible con IPv4 e IPv6)
    """
    rt = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])['RouteTables'][0]
    rows = []
    for route in rt['Routes']:
        # SOLUCIÓN: Usar .get() para obtener de forma segura el destino, sea IPv4 o IPv6
        destination = route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock', 'N/A')
        
        # El resto de la lógica para encontrar el target es seguro
        target = next((v for k, v in route.items() if 'Destination' not in k and (k.endswith('Id') or k.endswith('id'))), 'local')
        rows.append([destination, target, route.get('State', 'N/A')])
        
    return _format_to_table(['Destination', 'Target', 'State'], rows, f"Details for Route Table: {rtb_id}")


def pg_get_ec2_details(ec2_client, instance_id):
    """
    Gets network details for an EC2 instance.

    Args:
        ec2_client (boto3.client): The EC2 client.
        instance_id (str): The ID of the EC2 instance.

    Returns:
        dict: A dictionary with network details (IP, subnet, VPC, SGs).
    """
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        if not instance.get('PrivateIpAddress'):
            raise ValueError(f"EC2 instance '{instance_id}' has no private IP (it may be stopped).")
        return {"id": instance_id, "service": "EC2", "private_ip": instance['PrivateIpAddress'], "subnet_id": instance['SubnetId'], "vpc_id": instance['VpcId'], "security_group_ids": [sg['GroupId'] for sg in instance['SecurityGroups']]}
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            raise ValueError(f"EC2 instance with ID '{instance_id}' not found.")
        raise


def pg_get_rds_details(session, region, db_identifier, ec2_client):
    """
    Gets network details for an RDS instance.

    Args:
        session (boto3.Session): The boto3 session.
        region (str): The AWS region of the instance.
        db_identifier (str): The identifier of the RDS instance.
        ec2_client (boto3.client): An initialized EC2 client.

    Returns:
        dict: A dictionary with network details.
    """
    rds_client = session.client('rds', region_name=region)
    try:
        db = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)['DBInstances'][0]
        if db.get('PubliclyAccessible', False):
            raise ValueError(f"Unsupported analysis: RDS instance '{db_identifier}' is publicly accessible. This tool only analyzes private VPC routes.")
        
        endpoint = db.get('Endpoint', {}).get('Address')
        if not endpoint:
            raise ValueError(f"RDS instance '{db_identifier}' has no endpoint.")

        private_ip = socket.gethostbyname(endpoint)
        all_subnets_in_vpc = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [db['DBSubnetGroup']['VpcId']]}])['Subnets']
        current_subnet_id = next((s['SubnetId'] for s in all_subnets_in_vpc if ipaddress.ip_address(private_ip) in ipaddress.ip_network(s['CidrBlock'])), None)
        
        if not current_subnet_id:
            raise ValueError(f"Could not determine the subnet for RDS instance IP {private_ip}.")

        return {"id": db_identifier, "service": "RDS", "private_ip": private_ip, "subnet_id": current_subnet_id, "vpc_id": db['DBSubnetGroup']['VpcId'], "security_group_ids": [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]}
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            raise ValueError(f"RDS instance with identifier '{db_identifier}' not found.")
        raise


def pg_get_lambda_details(session, region, function_name, ec2_client):
    """
    Gets network details for a Lambda function within a VPC.

    Args:
        session (boto3.Session): The boto3 session.
        region (str): The AWS region of the function.
        function_name (str): The name of the Lambda function.
        ec2_client (boto3.client): An initialized EC2 client.

    Returns:
        dict: A dictionary with network details.
    """
    lambda_client = session.client('lambda', region_name=region)
    try:
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        vpc_config = config.get('VpcConfig')
        if not (vpc_config and vpc_config.get('VpcId')):
            raise ValueError(f"Lambda function '{function_name}' is not in a VPC.")

        paginator = ec2_client.get_paginator('describe_network_interfaces')
        pages = paginator.paginate(Filters=[{'Name': 'group-id', 'Values': vpc_config['SecurityGroupIds']}, {'Name': 'description', 'Values': [f'AWS Lambda VPC ENI-{function_name}-*']}])
        eni = next((eni for page in pages for eni in page['NetworkInterfaces']), None)

        if not (eni and eni.get('PrivateIpAddress')):
            raise ValueError(f"Could not find a network interface (ENI) with a private IP for Lambda '{function_name}'.")

        return {"id": function_name, "service": "Lambda", "private_ip": eni['PrivateIpAddress'], "subnet_id": eni['SubnetId'], "vpc_id": eni['VpcId'], "security_group_ids": [sg['GroupId'] for sg in eni['Groups']]}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise ValueError(f"Lambda function with name '{function_name}' not found.")
        raise


def pg_get_resource_network_details(session, arn):
    """
    Dispatcher function to get network details for any supported resource ARN.

    Args:
        session (boto3.Session): The boto3 session.
        arn (str): The ARN of the resource.

    Returns:
        dict: A dictionary containing the resource's network details.

    Example:
        >>> details = pg_get_resource_network_details(session, 'arn:aws:ec2:us-east-1:123:instance/i-123')
    """
    try:
        parts = arn.split(':')
        service, region, resource_full = parts[2], parts[3], ":".join(parts[5:])
        ec2_client = session.client('ec2', region_name=region)

        if service == 'ec2' and resource_full.startswith('instance/'):
            return pg_get_ec2_details(ec2_client, resource_full.split('/')[1])
        elif service == 'rds' and resource_full.startswith('db:'):
            return pg_get_rds_details(session, region, resource_full[3:], ec2_client)
        elif service == 'lambda' and resource_full.startswith('function:'):
            return pg_get_lambda_details(session, region, resource_full[9:], ec2_client)
        else:
            raise ValueError(f"Unsupported ARN type: '{arn}'. Supported: EC2 instances, RDS instances, Lambda functions.")
    except (IndexError, AttributeError):
        raise ValueError(f"Invalid ARN format: '{arn}'.")


def pg_check_nacl_fully(ec2_client, subnet_id, direction, remote_ip, protocol, port):
    """
    Evaluates NACL rules to determine if traffic is allowed or denied.

    Args:
        ec2_client (boto3.client): The EC2 client.
        subnet_id (str): The subnet ID to check.
        direction (str): 'inbound' or 'outbound'.
        remote_ip (str): The remote IP address for the traffic.
        protocol (str): The protocol number ('6', '17', etc.).
        port (int): The destination port number.

    Returns:
        tuple: (bool, dict) indicating if traffic is allowed and the matched rule.
    """
    try:
        acl = ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])['NetworkAcls'][0]
    except (IndexError, ClientError):
        vpc_id = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]['VpcId']
        acl = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'default', 'Values': ['true']}])['NetworkAcls'][0]

    rules = sorted([e for e in acl['Entries'] if e['Egress'] == (direction == 'outbound')], key=lambda x: x['RuleNumber'])
    for rule in rules:
        if rule['RuleNumber'] == 32767: continue
        if not (rule.get('CidrBlock') and ipaddress.ip_address(remote_ip) in ipaddress.ip_network(rule['CidrBlock'])): continue
        if rule.get('Protocol') not in ['-1', str(protocol)]: continue

        port_range = rule.get('PortRange', {})
        if 'From' in port_range and not (port >= port_range['From'] and port <= port_range['To']): continue

        matched_rule = {**rule, 'AclId': acl['NetworkAclId']}
        return rule['RuleAction'] == 'allow', matched_rule

    implicit_deny = {'RuleNumber': '*', 'RuleAction': 'deny', 'AclId': acl['NetworkAclId'], 'CidrBlock': '0.0.0.0/0'}
    return False, implicit_deny

def pg_check_route_table(ec2_client, source_subnet_id, dest_ip):
    """
    Checks the route table for a subnet to find a route for a destination IP.
    (Esta versión es compatible con IPv4 e IPv6)
    """
    try:
        response = ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [source_subnet_id]}])
        if not response['RouteTables']:
            vpc_id = ec2_client.describe_subnets(SubnetIds=[source_subnet_id])['Subnets'][0]['VpcId']
            response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'association.main', 'Values': ['true']}])
        rt = response['RouteTables'][0]

        matching_routes = []
        dest_addr = ipaddress.ip_address(dest_ip)
        
        for r in rt['Routes']:
            # SOLUCIÓN: Obtener el CIDR de forma segura (IPv4 o IPv6)
            cidr = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
            if not cidr:
                continue

            try:
                # Comprobar si la IP de destino pertenece a la red de la ruta
                if dest_addr in ipaddress.ip_network(cidr):
                    matching_routes.append(r)
            except TypeError:
                # Esto evita errores si se compara una IP v4 con una red v6 o viceversa
                continue

        if not matching_routes:
            return False, {'RouteTableId': rt.get('RouteTableId', 'N/A'), 'Target': 'No Route Found'}
        
        # Encontrar la ruta más específica (prefijo de red más largo)
        best_route = max(matching_routes, key=lambda r: ipaddress.ip_network(r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')).prefixlen)

        if best_route:
            target = next((v for k, v in best_route.items() if k.endswith('Id')), 'local')
            destination_cidr = best_route.get('DestinationCidrBlock') or best_route.get('DestinationIpv6CidrBlock')
            return True, {'RouteTableId': rt['RouteTableId'], 'Destination': destination_cidr, 'Target': target}
            
    except (ClientError, IndexError):
        pass
    return False, {'RouteTableId': 'N/A', 'Target': 'No Route Found'}

def pg_build_decision_table(path_info, consolidated_ports):
    """
    Builds a summary table of the network path decision.

    Args:
        path_info (dict): Dictionary with all rule details for the path.
        consolidated_ports (str): A formatted string of allowed ports.

    Returns:
        str: A formatted string table summarizing the path.
    """
    def get_sg_source_dest(rule):
        if 'IpRanges' in rule and rule['IpRanges']: return rule['IpRanges'][0].get('CidrIp', 'N/A')
        if 'UserIdGroupPairs' in rule and rule['UserIdGroupPairs']: return rule['UserIdGroupPairs'][0].get('GroupId', 'N/A')
        return 'N/A'
    
    sg_out = path_info['source_sg_rule']
    nacl_out = path_info['source_nacl_rule']
    route_info = path_info['route_rule']
    nacl_in = path_info['target_nacl_rule']
    sg_in = path_info['target_sg_rule']
    
    rows_data = [
        ["Source SG", path_info['source_sg_id'], "Egress", "N/A", "allow", PROTOCOLS.get(str(sg_out.get('IpProtocol','-1'))), f"{sg_out.get('FromPort', 'All')}-{sg_out.get('ToPort', 'All')}", get_sg_source_dest(sg_out)],
        ["Source NACL", nacl_out.get('AclId'), "Egress", str(nacl_out.get('RuleNumber')), nacl_out.get('RuleAction'), PROTOCOLS.get(str(nacl_out.get('Protocol','-1'))), f"{nacl_out.get('PortRange',{}).get('From','All')}-{nacl_out.get('PortRange',{}).get('To','All')}", nacl_out.get('CidrBlock')],
        ["Route Table", route_info.get('RouteTableId'), "Forwarding", route_info.get('Destination'), "N/A", "N/A", "N/A", route_info.get('Target')],
        ["Target NACL", nacl_in.get('AclId'), "Ingress", str(nacl_in.get('RuleNumber')), nacl_in.get('RuleAction'), PROTOCOLS.get(str(nacl_in.get('Protocol','-1'))), f"{nacl_in.get('PortRange',{}).get('From','All')}-{nacl_in.get('PortRange',{}).get('To','All')}", nacl_in.get('CidrBlock')],
        ["Target SG", path_info['target_sg_id'], "Ingress", "N/A", "allow", PROTOCOLS.get(str(sg_in.get('IpProtocol','-1'))), consolidated_ports, get_sg_source_dest(sg_in)],
    ]
    return _format_to_table(["Layer", "Resource ID", "Direction", "Rule/Dest", "Action", "Protocol", "Port(s)", "Source/Target"], rows_data, f"Decision Path for {consolidated_ports}:")


def pg_consolidate_ports(port_tuples):
    """
    Consolidates port/protocol tuples into a human-readable string.

    Args:
        port_tuples (list): List of (protocol, from_port, to_port) tuples.

    Returns:
        str: A formatted, consolidated string of ports and protocols.
    """
    ports_by_proto = defaultdict(set)
    for proto, from_port, to_port in port_tuples:
        proto_str = PROTOCOLS.get(str(proto), str(proto))
        if from_port == -1:
            ports_by_proto[proto_str] = {"All"}
            continue
        ports_by_proto[proto_str].add(f"{from_port}-{to_port}" if from_port != to_port else str(from_port))

    output_parts = []
    for proto, ports in sorted(ports_by_proto.items()):
        if "All" in ports:
            output_parts.append(f"All ports ({proto})")
            continue
        sorted_ports = sorted(list(ports), key=lambda x: tuple(map(int, x.split('-'))) if '-' in x else (int(x),))
        output_parts.append(f"Port(s) {', '.join(sorted_ports)} ({proto})")
    return " | ".join(output_parts)

def _get_nacl_for_subnet(ec2_client, subnet_id):
    """
    Función auxiliar para obtener el ID de la Network ACL para una subred determinada.
    """
    try:
        # Primero, buscar una asociación explícita
        acl_response = ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        if acl_response['NetworkAcls']:
            return acl_response['NetworkAcls'][0]['NetworkAclId']
        
        # Si no hay asociación, obtener la NACL por defecto de la VPC
        subnet_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
        if not subnet_response['Subnets']:
            return None
        vpc_id = subnet_response['Subnets'][0]['VpcId']
        default_acl_response = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'default', 'Values': ['true']}])
        if default_acl_response['NetworkAcls']:
            return default_acl_response['NetworkAcls'][0]['NetworkAclId']
            
    except (ClientError, IndexError):
        # Devolver None si alguna llamada a la API o acceso a la lista falla
        return None
    return None




def analyze_network_path_data(session, source_arn, target_arn):
    """
    Analiza la ruta de red entre dos recursos de AWS dentro de la misma VPC.
    (Versión actualizada que muestra detalles también en caso de fallo).
    """
    source = pg_get_resource_network_details(session, source_arn)
    target = pg_get_resource_network_details(session, target_arn)

    if source['vpc_id'] != target['vpc_id']:
        return {'status': 'UNREACHABLE', 'reason': f"Resources are in different VPCs ({source['vpc_id']} vs {target['vpc_id']})."}

    ec2 = session.client('ec2', region_name=source_arn.split(':')[3])
    route_ok, route_rule = pg_check_route_table(ec2, source['subnet_id'], target['private_ip'])
    
    # Si no hay ruta, poblamos los detalles y salimos directamente
    if not route_ok:
        result = {'status': 'UNREACHABLE', 'reason': f"No route found from source subnet to target IP '{target['private_ip']}'.", 'tables': [], 'detail_tables': {}}
        involved_ids = set([("rtb", route_rule.get('RouteTableId'))])
        involved_ids.update([("sg", sg_id) for sg_id in source['security_group_ids']])
        involved_ids.update([("sg", sg_id) for sg_id in target['security_group_ids']])
        
        for type, res_id in sorted(list(involved_ids)):
            if res_id and res_id != 'N/A':
                 if type == "sg": result['detail_tables'][res_id] = pg_format_sg_rules(ec2, res_id)
                 elif type == "rtb": result['detail_tables'][res_id] = pg_format_route_table(ec2, res_id)
        return result


    result = {'status': 'UNREACHABLE', 'reason': 'No SG rules allow the connection.', 'perms': [], 'tables': [], 'detail_tables': {}}
    source_sgs = ec2.describe_security_groups(GroupIds=source['security_group_ids'])['SecurityGroups']
    target_sgs = ec2.describe_security_groups(GroupIds=target['security_group_ids'])['SecurityGroups']

    for sg_out in source_sgs:
        for egress in sg_out.get('IpPermissionsEgress', []):
            target_matches = any(ipaddress.ip_address(target['private_ip']) in ipaddress.ip_network(ip.get('CidrIp')) for ip in egress.get('IpRanges',[])) or \
                             any(ref.get('GroupId') in target['security_group_ids'] for ref in egress.get('UserIdGroupPairs', []))
            if not target_matches: continue

            for sg_in in target_sgs:
                for ingress in sg_in.get('IpPermissions', []):
                    egress_proto, ingress_proto = egress.get('IpProtocol', '-1'), ingress.get('IpProtocol', '-1')
                    if egress_proto not in [ingress_proto, '-1'] and ingress_proto != '-1': continue
                    
                    e_from, e_to = egress.get('FromPort',-1), egress.get('ToPort',-1)
                    i_from, i_to = ingress.get('FromPort',-1), ingress.get('ToPort',-1)
                    if e_from != -1 and i_from != -1 and max(e_from, i_from) > min(e_to, i_to): continue
                    
                    source_matches = any(ipaddress.ip_address(source['private_ip']) in ipaddress.ip_network(ip.get('CidrIp')) for ip in ingress.get('IpRanges',[])) or \
                                     any(ref.get('GroupId') in source['security_group_ids'] for ref in ingress.get('UserIdGroupPairs', []))
                    if not source_matches: continue
                    
                    proto = ingress_proto if egress_proto == '-1' else egress_proto
                    port = ingress.get('FromPort',-1) if egress.get('FromPort',-1) == -1 else egress.get('FromPort',-1)
                    
                    nacl_out_ok, nacl_out_rule = pg_check_nacl_fully(ec2, source['subnet_id'], 'outbound', target['private_ip'], proto, port)
                    if not nacl_out_ok:
                        result['reason'] = f"Blocked by outbound NACL rule #{nacl_out_rule.get('RuleNumber')} in {nacl_out_rule.get('AclId')}"
                        continue
                    
                    nacl_in_ok, nacl_in_rule = pg_check_nacl_fully(ec2, target['subnet_id'], 'inbound', source['private_ip'], proto, port)
                    if not nacl_in_ok:
                        result['reason'] = f"Blocked by inbound NACL rule #{nacl_in_rule.get('RuleNumber')} in {nacl_in_rule.get('AclId')}"
                        continue

                    result['status'] = 'REACHABLE'
                    result['perms'].append({'perm_tuple': (ingress_proto, i_from, ingress.get('ToPort', -1)), 'source_sg_rule': egress, 'source_sg_id': sg_out['GroupId'], 'target_sg_rule': ingress, 'target_sg_id': sg_in['GroupId'], 'source_nacl_rule': nacl_out_rule, 'target_nacl_rule': nacl_in_rule, 'route_rule': route_rule})

    # --- INICIO DE LA SECCIÓN MODIFICADA ---
    involved_ids = set()

    if result['status'] == 'REACHABLE':
        result['reason'] = ''
        grouped_paths = defaultdict(list)
        for p in result['perms']:
            sig = (p['source_sg_id'], p['target_sg_id'], p['source_nacl_rule']['AclId'], p['target_nacl_rule']['AclId'], str(p['route_rule']))
            grouped_paths[sig].append(p['perm_tuple'])
            # Popular IDs desde la ruta exitosa
            involved_ids.update([
                ("sg", p['source_sg_id']), 
                ("sg", p['target_sg_id']), 
                ("nacl", p['source_nacl_rule']['AclId']), 
                ("nacl", p['target_nacl_rule']['AclId']), 
                ("rtb", p['route_rule']['RouteTableId'])
            ])
        
        for sig, perms in grouped_paths.items():
            path_info = next(p for p in result['perms'] if p['perm_tuple'] in perms)
            result['tables'].append(pg_build_decision_table(path_info, pg_consolidate_ports(perms)))

    else: # status es UNREACHABLE
        # Recopilar proactivamente todos los recursos potencialmente involucrados
        involved_ids.update([("sg", sg_id) for sg_id in source['security_group_ids']])
        involved_ids.update([("sg", sg_id) for sg_id in target['security_group_ids']])
        
        if route_rule.get('RouteTableId') and route_rule['RouteTableId'] != 'N/A':
            involved_ids.add(("rtb", route_rule['RouteTableId']))
        
        source_nacl_id = _get_nacl_for_subnet(ec2, source['subnet_id'])
        if source_nacl_id:
            involved_ids.add(("nacl", source_nacl_id))

        target_nacl_id = _get_nacl_for_subnet(ec2, target['subnet_id'])
        if target_nacl_id:
            involved_ids.add(("nacl", target_nacl_id))

    # Poblar incondicionalmente las tablas de detalles a partir de los IDs recopilados
    for type, res_id in sorted(list(involved_ids)):
        if res_id and res_id not in result['detail_tables']:
            if type == "sg": result['detail_tables'][res_id] = pg_format_sg_rules(ec2, res_id)
            elif type == "nacl": result['detail_tables'][res_id] = pg_format_nacl_rules(ec2, res_id)
            elif type == "rtb": result['detail_tables'][res_id] = pg_format_route_table(ec2, res_id)
                
    del result['perms']
    return result


def simulate_user_permissions(session, username, actions, context_entries=None):
    """
    Simulates permissions for a specific IAM user using simulate_principal_policy.
    
    Args:
        session (boto3.Session): The boto3 session.
        username (str): The IAM username to simulate.
        actions (list): List of actions to test.
        context_entries (list): Optional context entries (e.g., MFA conditions).
    
    Returns:
        dict: Results of the simulation with detailed evaluation.
    """
    iam_client = session.client("iam")
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    user_arn = f"arn:aws:iam::{account_id}:user/{username}"
    
    try:
        response = iam_client.simulate_principal_policy(
            PolicySourceArn=user_arn,
            ActionNames=actions,
            ContextEntries=context_entries or []
        )
        
        results = []
        for eval_result in response.get('EvaluationResults', []):
            results.append({
                'action': eval_result['EvalActionName'],
                'decision': eval_result['EvalDecision'],
                'matched_statements': eval_result.get('MatchedStatements', []),
                'missing_context_values': eval_result.get('MissingContextValues', [])
            })
        
        return {
            'username': username,
            'user_arn': user_arn,
            'simulation_results': results,
            'context_applied': context_entries or []
        }
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            raise ValueError(f"User '{username}' not found.")
        raise Exception(f"Simulation failed: {str(e)}")
    
def simulate_lambda_permissions(session, function_name, region, actions, context_entries=None):
    """
    Simula permisos para una función Lambda usando el rol de ejecución de la función.
    """
    lambda_client = session.client("lambda", region_name=region)
    iam_client = session.client("iam")
    
    try:
        # Obtener la configuración de la función Lambda
        function_config = lambda_client.get_function_configuration(FunctionName=function_name)
        execution_role_arn = function_config['Role']
        
        # Simular con el rol de ejecución
        response = iam_client.simulate_principal_policy(
            PolicySourceArn=execution_role_arn,
            ActionNames=actions,
            ContextEntries=context_entries or []
        )
        
        results = []
        for eval_result in response.get('EvaluationResults', []):
            results.append({
                'action': eval_result['EvalActionName'],
                'decision': eval_result['EvalDecision'],
                'matched_statements': eval_result.get('MatchedStatements', []),
                'missing_context_values': eval_result.get('MissingContextValues', [])
            })
        
        return {
            'function_name': function_name,
            'execution_role_arn': execution_role_arn,
            'simulation_results': results,
            'context_applied': context_entries or []
        }
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise ValueError(f"Lambda function '{function_name}' not found.")
        raise Exception(f"Simulation failed: {str(e)}")
    
