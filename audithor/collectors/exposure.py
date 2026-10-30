import json
import boto3
import threading
from botocore.exceptions import ClientError
from collections import defaultdict
from .utils import get_all_aws_regions # Relative import

EXPOSURE_SERVICES = {
    "S3 Public Buckets": "s3",
    "EC2 Public Instances": "ec2",
    "Security Groups Open": "ec2",
    "ALB/NLB Public": "elbv2",
    "Lambda URLs": "lambda",
    "API Gateway Public": "apigateway",
    "Route53 Subdomains": "route53",
    "Assumable Roles": "iam",
}

EXPOSURE_GLOBAL_SERVICES = {"S3 Public Buckets", "Route53 Subdomains", "Assumable Roles"}


def is_bucket_public(s3, bucket):
    """
    Checks if an S3 bucket is public via ACL or bucket policy.

    Args:
        s3 (boto3.client): The S3 client object.
        bucket (dict): A dictionary containing the bucket's name.

    Returns:
        bool: True if the bucket is public, False otherwise.

    Example:
        >>> s3_client = boto3.client('s3')
        >>> bucket_info = {'Name': 'my-test-bucket'}
        >>> is_public = is_bucket_public(s3_client, bucket_info)
    """
    try:
        acl = s3.get_bucket_acl(Bucket=bucket["Name"])
        for grant in acl.get("Grants", []):
            if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                return True
    except ClientError:
        pass  # Ignore errors like AccessDenied

    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket["Name"])
        if policy_status.get("PolicyStatus", {}).get("IsPublic"):
            return True
    except ClientError:
        pass  # Ignore errors if no policy exists or access is denied

    return False


def lambda_has_url(client, fn_name):
    """
    Determines if a Lambda function has a public Function URL.

    A function URL is considered public if its authentication type is 'NONE'.

    Args:
        client (boto3.client): The Lambda client object.
        fn_name (str): The name of the Lambda function.

    Returns:
        bool: True if the function has a public URL, False otherwise.

    Example:
        >>> lambda_client = boto3.client('lambda')
        >>> has_public_url = lambda_has_url(lambda_client, 'my-function')
    """
    try:
        configs = client.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
        return any(c.get("AuthType") == "NONE" for c in configs)
    except ClientError:
        return False


def role_is_assumable_by_anyone(role):
    """
    Checks if an IAM role's trust policy allows it to be assumed by anyone.

    It inspects the 'Principal' in the assume role policy document.

    Args:
        role (dict): A dictionary representing the IAM role details.

    Returns:
        bool: True if the role is assumable by a wildcard principal, False otherwise.

    Example:
        >>> role_details = iam_client.get_role(RoleName='my-role')['Role']
        >>> is_assumable = role_is_assumable_by_anyone(role_details)
    """
    try:
        pol = role.get("AssumeRolePolicyDocument", {})
        for stmt in pol.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal.get("AWS") == "*":
                return True
    except Exception:
        pass
    return False


def collect_api_gateway_details(session, region):
    """
    Collects detailed API Gateway information for a specific region.
    
    Args:
        session (boto3.Session): The boto3 session to use for creating clients.
        region (str): The AWS region to scan.
    
    Returns:
        list: A list of dictionaries with detailed API Gateway information.
    """
    try:
        client = session.client("apigateway", region_name=region)
        apis = []
        
        # Get REST APIs
        rest_apis_response = client.get_rest_apis()
        for api in rest_apis_response.get("items", []):
            endpoint_config = api.get("endpointConfiguration", {})
            endpoint_types = endpoint_config.get("types", ["REGIONAL"])  # Default to REGIONAL if not specified
            
            # Check if it's a public API (Regional or Edge-optimized, exclude Private)
            public_endpoint_types = [t for t in endpoint_types if t in ["REGIONAL", "EDGE"]]
            if public_endpoint_types:
                integrations = []
                # Get additional details about stages
                try:
                    stages_response = client.get_stages(restApiId=api["id"])
                    stages = [stage["stageName"] for stage in stages_response.get("item", [])]
                    try:
                        resources_response = client.get_resources(restApiId=api["id"])
                        for resource in resources_response.get("items", []):
                            resource_path = resource.get("path")
                            for method_name in resource.get("resourceMethods", {}).keys():
                                try:
                                    # Get_integration nos dice qué hay detrás de este método
                                    integration = client.get_integration(
                                        restApiId=api["id"],
                                        resourceId=resource["id"],
                                        httpMethod=method_name
                                    )
                                    integrations.append({
                                        "path": resource_path,
                                        "method": method_name,
                                        "type": integration.get("type"),
                                        "uri": integration.get("uri")
                                    })
                                except ClientError:
                                    # Ignorar métodos sin integración (ej: OPTIONS)
                                    pass
                    except ClientError:
                        pass # No se pudieron obtener los resources
                except ClientError:
                    stages = []
                
                # Format endpoint types for display
                formatted_endpoint_types = []
                for et in public_endpoint_types:
                    if et == "REGIONAL":
                        formatted_endpoint_types.append("Regional")
                    elif et == "EDGE":
                        formatted_endpoint_types.append("Edge Optimized")
                
                api_info = {
                    "id": api["id"],
                    "name": api["name"],
                    "description": api.get("description", "No description"),
                    "createdDate": api.get("createdDate").isoformat() if api.get("createdDate") else None,
                    "version": api.get("version", "N/A"),
                    "endpointConfiguration": formatted_endpoint_types,
                    "stages": stages,
                    "region": region,
                    "apiType": "REST",
                    "integrations": integrations

                }
                apis.append(api_info)
        
        # Get HTTP APIs (API Gateway v2)
        try:
            apiv2_client = session.client("apigatewayv2", region_name=region)
            http_apis_response = apiv2_client.get_apis()
            
            for api in http_apis_response.get("Items", []):
                # HTTP APIs are typically public by default unless configured otherwise
                if api.get("ProtocolType") == "HTTP":
                    # Get stages for HTTP API
                    integrations = []
                    try:
                        stages_response = apiv2_client.get_stages(ApiId=api["ApiId"])
                        stages = [stage["StageName"] for stage in stages_response.get("Items", [])]
                        
                        try:
                            # 1. Obtenemos un mapa de todas las integraciones
                            integrations_map = {
                                integ["IntegrationId"]: integ 
                                for integ in apiv2_client.get_integrations(ApiId=api["ApiId"]).get("Items", [])
                            }

                            # 2. Obtenemos las rutas y las mapeamos a las integraciones
                            routes_response = apiv2_client.get_routes(ApiId=api["ApiId"])
                            for route in routes_response.get("Items", []):
                                target_id = route.get("Target", "").split('/')[-1]
                                integration = integrations_map.get(target_id, {})

                                integrations.append({
                                    "path": route.get("RouteKey"), # ej: "GET /pets"
                                    "method": "", # En V2 el método está en el 'path'
                                    "type": integration.get("IntegrationType"),
                                    "uri": integration.get("IntegrationUri")
                                })
                        except ClientError:
                            pass # No se pudieron obtener las rutas/integraciones
                    except ClientError:
                        stages = []
                    
                    api_info = {
                        "id": api["ApiId"],
                        "name": api["Name"],
                        "description": api.get("Description", "No description"),
                        "createdDate": api.get("CreatedDate").isoformat() if api.get("CreatedDate") else None,
                        "version": api.get("Version", "N/A"),
                        "endpointConfiguration": ["Regional"],  # HTTP APIs are regional by default
                        "stages": stages,
                        "region": region,
                        "apiType": "HTTP",
                        "integrations": integrations
                    }
                    apis.append(api_info)
        except ClientError:
            # API Gateway v2 might not be available in all regions
            pass
            
        return apis
        
    except ClientError as e:
        if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 
                                          'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
            return []
        raise
    except Exception:
        return []


def collect_network_ports_data(session, regions):
    """
    Scans Security Groups and Network ACLs across regions for rules allowing inbound traffic from 0.0.0.0/0.

    Args:
        session (boto3.Session): The boto3 session to use for creating clients.
        regions (list): A list of AWS region names to scan.

    Returns:
        list: A list of dictionaries, each detailing an exposed port or range.

    Example:
        >>> current_session = boto3.Session()
        >>> regions_to_scan = ['us-east-1', 'eu-west-1']
        >>> ports = collect_network_ports_data(current_session, regions_to_scan)
    """
    exposed_ports = []

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            from_port = perm.get("FromPort", "All")
                            to_port = perm.get("ToPort", "All")
                            exposed_ports.append({
                                "Region": region, "ResourceId": sg.get("GroupId"), "ResourceType": "SecurityGroup",
                                "Direction": "Inbound", "Protocol": perm.get("IpProtocol"),
                                "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                "Source": ip_range.get("CidrIp"), "Description": f"SG: {sg.get('GroupName')}"
                            })

            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                for entry in acl.get("Entries", []):
                    if entry.get("RuleAction") == "allow" and not entry.get("Egress") and entry.get("CidrBlock") == "0.0.0.0/0":
                        port_range = entry.get("PortRange", {})
                        from_port = port_range.get("From", "All")
                        to_port = port_range.get("To", "All")
                        exposed_ports.append({
                            "Region": region, "ResourceId": acl.get("NetworkAclId"), "ResourceType": "NetworkAcl",
                            "Direction": "Inbound", "Protocol": "All" if entry.get("Protocol") == -1 else entry.get("Protocol"),
                            "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                            "Source": entry.get("CidrBlock"), "Description": f"NACL Rule Number: {entry.get('RuleNumber')}"
                        })
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
    return exposed_ports


def collect_exposure_data(session):
    """
    Collects public exposure data across multiple AWS services using multi-threading.

    This function scans for public S3 buckets, EC2 instances, open security groups,
    internet-facing load balancers, Lambda URLs, public API Gateways, and
    publicly assumable IAM roles. It also collects open network port data.

    Args:
        session (boto3.Session): The boto3 session for creating service clients.

    Returns:
        dict: A dictionary containing a summary, detailed findings, and network port analysis.

    Example:
        >>> current_session = boto3.Session()
        >>> exposure_report = collect_exposure_data(current_session)
    """
    regions = get_all_aws_regions(session)
    result_summary = defaultdict(dict)
    result_details = defaultdict(lambda: defaultdict(list))
    lock = threading.Lock()
    threads = []
    network_ports_results = collect_network_ports_data(session, regions)

    def worker(service, region, current_session):
        try:
            exposed = []
            if service == "S3 Public Buckets":
                client = current_session.client("s3", region_name=region if region != "Global" else "us-east-1")
                for b in client.list_buckets()["Buckets"]:
                    if is_bucket_public(client, b):
                        exposed.append(b["Name"])

            elif service == "EC2 Public Instances":
                client = current_session.client("ec2", region_name=region)
                for r in client.describe_instances()["Reservations"]:
                    for inst in r["Instances"]:
                        if inst.get("PublicIpAddress"):
                            exposed.append({"Id": inst['InstanceId'], "State": inst.get("State", {}).get("Name", "unknown"), "PublicIp": inst.get("PublicIpAddress")})

            elif service == "Security Groups Open":
                client = current_session.client("ec2", region_name=region)
                sgs = client.describe_security_groups().get("SecurityGroups", [])
                for sg in sgs:
                    for perm in sg.get("IpPermissions", []):
                        if any(ip_range.get("CidrIp") == "0.0.0.0/0" for ip_range in perm.get("IpRanges", [])):
                            protocol_map = {'-1': 'ALL', 'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP'}
                            protocol = protocol_map.get(str(perm.get("IpProtocol")).lower(), perm.get("IpProtocol"))
                            
                            from_port = perm.get("FromPort")
                            to_port = perm.get("ToPort")
                            
                            port_range = "All"
                            if from_port is not None and to_port is not None:
                                if from_port == to_port:
                                    port_range = str(from_port)
                                else:
                                    port_range = f"{from_port}-{to_port}"

                            exposed.append({
                                "GroupId": sg['GroupId'],
                                "GroupName": sg['GroupName'],
                                "Protocol": protocol,
                                "PortRange": port_range,
                                "Region": region
                            })

            elif service == "ALB/NLB Public":
                client = current_session.client("elbv2", region_name=region)
                ssl_policies_details = {p['Name']: p for p in client.describe_ssl_policies().get('SslPolicies', [])}
                for lb in client.describe_load_balancers()["LoadBalancers"]:
                    if lb.get("Scheme") == "internet-facing":
                        lb_arn = lb["LoadBalancerArn"]
                        listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                        listener_details = []
                        for listener in listeners:
                            if listener.get("Protocol") in ["HTTPS", "TLS"]:
                                policy_name = listener.get("SslPolicy")
                                policy_details = ssl_policies_details.get(policy_name, {})
                                tls_versions = policy_details.get('SslProtocols', [])
                                ciphers = [c['Name'] for c in policy_details.get('Ciphers', [])]
                                is_outdated = any(v in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for v in tls_versions)
                                listener_details.append({
                                    "port": listener.get("Port"), "protocol": listener.get("Protocol"),
                                    "policyName": policy_name, "isOutdated": is_outdated,
                                    "tlsVersions": tls_versions, "ciphers": ciphers
                                })
                        exposed.append({
                            "name": lb["LoadBalancerName"], "arn": lb_arn,
                            "region": region, "listeners": listener_details
                        })

            elif service == "Lambda URLs":
                client = current_session.client("lambda", region_name=region)
                for fn in client.list_functions()["Functions"]:
                    if lambda_has_url(client, fn["FunctionName"]):
                        exposed.append(fn["FunctionName"])

            elif service == "API Gateway Public":
                # Use the new detailed collection function
                exposed = collect_api_gateway_details(current_session, region)

            elif service == "Assumable Roles":
                client = current_session.client("iam", region_name="us-east-1")
                for role in client.list_roles()["Roles"]:
                    if role_is_assumable_by_anyone(role):
                        exposed.append(role["RoleName"])

            elif service == "Route53 Subdomains":
                client = current_session.client("route53", region_name="us-east-1")
                hosted_zone_paginator = client.get_paginator("list_hosted_zones")
                for hosted_zone_page in hosted_zone_paginator.paginate():
                    for hosted_zone in hosted_zone_page.get("HostedZones", []):
                        zone_id = hosted_zone.get("Id", "").split("/")[-1]
                        zone_name = hosted_zone.get("Name", "").rstrip(".")

                        if not zone_id or not zone_name:
                            continue

                        paginator = client.get_paginator("list_resource_record_sets")
                        for page in paginator.paginate(HostedZoneId=zone_id):
                            for record in page.get("ResourceRecordSets", []):
                                record_name = record.get("Name", "").rstrip(".")
                                record_type = record.get("Type", "")

                                if not record_name:
                                    continue

                                is_apex = record_name == zone_name
                                is_dns_meta = record_type in {"NS", "SOA"}
                                is_subdomain = record_name.endswith(f".{zone_name}") and not is_apex

                                if is_subdomain and not is_dns_meta:
                                    exposed.append({
                                        "HostedZone": zone_name,
                                        "Name": record_name,
                                        "Type": record_type,
                                        "TTL": record.get("TTL", "Alias")
                                    })

            with lock:
                if exposed:
                    result_summary[service][region] = len(exposed)
                    result_details[service][region] = exposed
        except ClientError:
            pass

    tasks = [(s, "Global") if s in EXPOSURE_GLOBAL_SERVICES else (s, r) for s in EXPOSURE_SERVICES for r in (["Global"] if s in EXPOSURE_GLOBAL_SERVICES else regions)]
    for service, region in tasks:
        t = threading.Thread(target=worker, args=(service, region, session))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return {
        "summary": dict(result_summary),
        "details": dict(result_details),
        "network_ports": network_ports_results
    }

def scan_lambda_credentials(session):
    """
    Escanea funciones Lambda buscando credenciales hardcodeadas en variables de entorno,
    código fuente y configuración.
    """
    regions = get_all_aws_regions(session)
    credential_findings = []
    
    # Patrones para detectar credenciales
    sensitive_patterns = [
        r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
        r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
        r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9+/]{20,})["\']?',
        r'(?i)(access[_-]?key|accesskey)\s*[=:]\s*["\']?(AKIA[a-zA-Z0-9]{16})["\']?',
        r'(?i)(token)\s*[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
        r'(?i)(database[_-]?url|db[_-]?url)\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'(?i)(connection[_-]?string)\s*[=:]\s*["\']?([^"\'\s]+)["\']?'
    ]
    
    sensitive_env_names = [
        'PASSWORD', 'PASSWD', 'PWD', 'API_KEY', 'APIKEY', 'SECRET_KEY', 'SECRETKEY',
        'ACCESS_KEY', 'ACCESSKEY', 'TOKEN', 'AUTH_TOKEN', 'JWT_SECRET', 'DB_PASSWORD',
        'DATABASE_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD', 'REDIS_PASSWORD',
        'DATABASE_URL', 'DB_URL', 'CONNECTION_STRING', 'PRIVATE_KEY', 'RSA_PRIVATE_KEY'
    ]
    
    for region in regions:
        try:
            lambda_client = session.client('lambda', region_name=region)
            
            # Obtener todas las funciones Lambda
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    function_name = function['FunctionName']
                    function_arn = function['FunctionArn']
                    
                    try:
                        # Obtener configuración detallada
                        config = lambda_client.get_function(FunctionName=function_name)
                        env_vars = config['Configuration'].get('Environment', {}).get('Variables', {})
                        
                        # Escanear variables de entorno
                        for env_name, env_value in env_vars.items():
                            # Verificar nombres sospechosos
                            if env_name.upper() in sensitive_env_names:
                                credential_findings.append({
                                    "type": "Suspicious Environment Variable Name",
                                    "severity": "HIGH",
                                    "region": region,
                                    "function_name": function_name,
                                    "function_arn": function_arn,
                                    "finding": f"Environment variable '{env_name}' has a sensitive name",
                                    "env_var_name": env_name,
                                    "env_var_value": env_value[:20] + "..." if len(env_value) > 20 else env_value,
                                    "runtime": config['Configuration'].get('Runtime', 'Unknown')
                                })
                            
                            # Verificar patrones en valores
                            for pattern in sensitive_patterns:
                                import re
                                matches = re.findall(pattern, env_value)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, tuple):
                                            key_name, potential_secret = match
                                        else:
                                            key_name, potential_secret = "unknown", match
                                        
                                        credential_findings.append({
                                            "type": "Potential Hardcoded Credential",
                                            "severity": "CRITICAL",
                                            "region": region,
                                            "function_name": function_name,
                                            "function_arn": function_arn,
                                            "finding": f"Potential {key_name} found in environment variable '{env_name}'",
                                            "env_var_name": env_name,
                                            "detected_pattern": key_name,
                                            "sample_value": potential_secret[:10] + "..." if len(potential_secret) > 10 else potential_secret,
                                            "runtime": config['Configuration'].get('Runtime', 'Unknown')
                                        })
                        
                        # Escanear código fuente (si es posible descargar)
                        try:
                            if config['Configuration'].get('PackageType') == 'Zip':
                                code_response = lambda_client.get_function(
                                    FunctionName=function_name,
                                    Qualifier='$LATEST'
                                )
                                
                                # Si el código es pequeño, intentar descargarlo y escanearlo
                                code_size = config['Configuration'].get('CodeSize', 0)
                                if code_size < 50 * 1024 * 1024:  # Menos de 50MB
                                    download_url = code_response['Code'].get('Location')
                                    if download_url:
                                        # Aquí podrías implementar descarga y análisis del código
                                        # Por ahora, solo registramos que existe código analizable
                                        credential_findings.append({
                                            "type": "Code Analysis Opportunity",
                                            "severity": "INFO",
                                            "region": region,
                                            "function_name": function_name,
                                            "function_arn": function_arn,
                                            "finding": f"Function code is downloadable and could contain hardcoded secrets (Size: {code_size} bytes)",
                                            "code_size": code_size,
                                            "runtime": config['Configuration'].get('Runtime', 'Unknown')
                                        })
                        except:
                            pass  # No se puede acceder al código
                            
                    except Exception as e:
                        print(f"Error analyzing Lambda function {function_name} in {region}: {e}")
                        continue
                        
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 
                                              'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
    
    return credential_findings
