# collectors/waf.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from .utils import get_all_aws_regions # Importación relativa


def parse_resource_arn(arn):
    """
    Parses an AWS ARN string to extract a simplified, human-readable resource identifier.

    This function is designed to handle different ARN formats, with special logic
    for complex ones like Elastic Load Balancers and API Gateway REST APIs to 
    provide more context than just the final ID. For all other ARNs, it defaults
    to returning the last component of the resource path.

    Args:
        arn (str): The full AWS ARN string to be parsed.

    Returns:
        str: The simplified resource name/ID, or the original ARN string if
             parsing fails due to an unexpected format.
    """
    try:
        parts = arn.split(':')
        resource_part = parts[5]
        if 'loadbalancer' in resource_part:
            lb_parts = resource_part.split('/')
            if len(lb_parts) > 2:
                return f"{lb_parts[0]}/{lb_parts[1]}/{lb_parts[2]}"
        if 'restapis' in resource_part:
            api_parts = resource_part.split('/')
            if len(api_parts) > 2:
                return f"{api_parts[1]}/{api_parts[2]}"
        # Para ARNs de API Gateway Stages
        if 'execute-api' in parts[2]:
            return f"apigw-stage/{resource_part.split('/')[-1]}"
        # Para ARNs de CloudFront
        if 'cloudfront' in parts[2]:
            return f"cloudfront/{resource_part.split('/')[-1]}"
        return resource_part.split('/')[-1]
    except Exception:
        return arn


def get_logging_configuration_details(client, acl_arn, scope):
    """
    Retrieves detailed logging configuration for a Web ACL, including both
    'All logging' and 'Logging destination only' configurations.
    
    Args:
        client: WAFv2 boto3 client
        acl_arn (str): ARN of the Web ACL
        scope (str): Scope of the Web ACL ('CLOUDFRONT' or 'REGIONAL')
    
    Returns:
        dict: Dictionary containing detailed logging configuration
    """
    logging_details = {
        'all_logging': {
            'enabled': False,
            'destinations': [],
            'log_filters': [],
            'default_behavior': None
        },
        'destination_only_logging': {
            'enabled': False,
            'destinations': [],
            'log_filters': [],
            'default_behavior': None
        }
    }
    
    try:
        # Get the full logging configuration
        response = client.get_logging_configuration(ResourceArn=acl_arn)
        logging_config = response.get('LoggingConfiguration', {})
        
        if logging_config:
            destinations = logging_config.get('LogDestinationConfigs', [])
            redacted_fields = logging_config.get('RedactedFields', [])
            log_filters = logging_config.get('LoggingFilter', {}).get('Filters', [])
            default_behavior = logging_config.get('LoggingFilter', {}).get('DefaultBehavior', 'KEEP')
            
            # Check if "All logging" is enabled (when LoggingFilter is not restrictive)
            all_logging_enabled = True
            if log_filters:
                # If there are filters, check if they are configured for selective logging
                destination_only_filters = [f for f in log_filters if f.get('Behavior') == 'KEEP']
                if destination_only_filters and default_behavior == 'DROP':
                    all_logging_enabled = False
            
            # Populate all_logging configuration
            if all_logging_enabled:
                logging_details['all_logging']['enabled'] = True
                logging_details['all_logging']['destinations'] = destinations
                logging_details['all_logging']['default_behavior'] = default_behavior
            
            # Populate destination_only_logging configuration
            if log_filters and default_behavior == 'DROP':
                logging_details['destination_only_logging']['enabled'] = True
                logging_details['destination_only_logging']['destinations'] = destinations
                logging_details['destination_only_logging']['log_filters'] = log_filters
                logging_details['destination_only_logging']['default_behavior'] = default_behavior
            
    except ClientError as e:
        # Logging configuration might not exist or access denied
        pass
    
    return logging_details


def collect_waf_data(session):
    """
    Collects data on AWS WAFv2 Web ACLs and IP Sets, including CloudWatch metrics for top rules
    and detailed logging configurations (both 'All logging' and 'Logging destination only').

    This function handles the dual-scope nature of WAFv2 by first querying for
    global resources (Scope='CLOUDFRONT') in us-east-1, and then iterating
    through all other regions for regional resources (Scope='REGIONAL').
    It gathers details for Web ACLs (logging, visibility) and IP Sets.
    
    For each Web ACL, it also queries CloudWatch for the 'BlockedRequests' metric
    over the last 30 days to identify the most triggered rules.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing two keys:
              - 'acls': A list of all Web ACLs, each including a 'TopRules' key 
                        with metric data if available and detailed logging configuration.
              - 'ip_sets': A list of all IP Sets, global and regional.
    """
    all_acls = []
    all_ip_sets = []
    regions = get_all_aws_regions(session)

    # Listas temporales para WAF Classic
    classic_global_acls = []
    classic_regional_acls = {} # Usaremos un diccionario para las regionales
    cloudfront_associations = get_cloudfront_to_waf_map(session)

    # --- 1. Collect CloudFront (Global) Web ACLs from WAFv2 ---
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_web_acls(Scope="CLOUDFRONT")
        for acl_summary in response.get("WebACLs", []):
            acl_details = client_global.get_web_acl(
                Name=acl_summary["Name"],
                Scope="CLOUDFRONT",
                Id=acl_summary["Id"]
            ).get("WebACL", {})

            resources_raw = client_global.list_resources_for_web_acl(
                WebACLArn=acl_summary["ARN"]
            ).get("ResourceArns", [])
            cloudfront_arns = cloudfront_associations.get(acl_summary["ARN"], [])
            resources_raw.extend(cloudfront_arns)
            
            logging_details = get_logging_configuration_details(
                client_global, acl_summary["ARN"], "CLOUDFRONT"
            )
            
            top_rules = []
            try:
                cloudwatch_client = session.client('cloudwatch', region_name="us-east-1")
                metric_response = cloudwatch_client.get_metric_data(
                    MetricDataQueries=[{
                        'Id': 'blocked_requests_by_rule',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/WAFV2',
                                'MetricName': 'BlockedRequests',
                                'Dimensions': [
                                    {'Name': 'WebACL', 'Value': acl_summary["Name"]},
                                    {'Name': 'Rule', 'Value': 'ALL'}
                                ]
                            },
                            'Period': 2592000,
                            'Stat': 'Sum',
                        },
                        'ReturnData': True,
                    }],
                    StartTime=datetime.utcnow() - timedelta(days=30),
                    EndTime=datetime.utcnow()
                )
                if metric_response.get('MetricDataResults'):
                    for result in metric_response['MetricDataResults']:
                        rule_name = result['Label']
                        total_blocked = sum(result['Values'])
                        if total_blocked > 0:
                            top_rules.append({"RuleName": rule_name, "BlockedRequests": int(total_blocked)})
            except ClientError:
                pass 

            all_acls.append({
                "Name": acl_summary["Name"],
                "ARN": acl_summary["ARN"],
                "Id": acl_summary["Id"],
                "Scope": "CLOUDFRONT",
                "Region": "Global",
                "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw],
                "LoggingConfiguration": acl_details.get("LoggingConfiguration", {}),
                "LoggingDetails": logging_details,
                "VisibilityConfig": acl_details.get("VisibilityConfig", {}),
                "TopRules": sorted(top_rules, key=lambda x: x['BlockedRequests'], reverse=True)
            })
    except ClientError:
        pass

    # --- 1.5. Collect CloudFront (Global) Web ACLs IDs from WAF Classic ---
    try:
        client_classic_global = session.client("waf", region_name="us-east-1")
        response_classic = client_classic_global.list_web_acls(Limit=100)
        
        for acl_summary in response_classic.get("WebACLs", []):
            classic_global_acls.append({
                "Name": f"{acl_summary['Name']} (Classic)",
                "Id": acl_summary["WebACLId"]
            })
    except ClientError as e:
        pass

    # --- 2. Collect Regional Web ACLs ---
    for region in regions:
        # --- 2.1 Regional WAFv2 ---
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_web_acls(Scope="REGIONAL")
            for acl_summary in response.get("WebACLs", []):
                acl_details = client_regional.get_web_acl(
                    Name=acl_summary["Name"],
                    Scope="REGIONAL",
                    Id=acl_summary["Id"]
                ).get("WebACL", {})

                resources_raw = client_regional.list_resources_for_web_acl(
                    WebACLArn=acl_summary["ARN"]
                ).get("ResourceArns", [])

                logging_details = get_logging_configuration_details(
                    client_regional, acl_summary["ARN"], "REGIONAL"
                )

                top_rules = []
                try:
                    cloudwatch_client = session.client('cloudwatch', region_name=region)
                    metric_response = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[{
                            'Id': 'blocked_requests_by_rule',
                            'MetricStat': {
                                'Metric': {
                                    'Namespace': 'AWS/WAFV2',
                                    'MetricName': 'BlockedRequests',
                                    'Dimensions': [
                                        {'Name': 'WebACL', 'Value': acl_summary["Name"]},
                                        {'Name': 'Rule', 'Value': 'ALL'}
                                    ]
                                },
                                'Period': 259200,
                                'Stat': 'Sum',
                            },
                            'ReturnData': True,
                        }],
                        StartTime=datetime.utcnow() - timedelta(days=3),
                        EndTime=datetime.utcnow()
                    )
                    if metric_response.get('MetricDataResults'):
                        for result in metric_response['MetricDataResults']:
                            rule_name = result['Label']
                            total_blocked = sum(result['Values'])
                            if total_blocked > 0:
                                top_rules.append({"RuleName": rule_name, "BlockedRequests": int(total_blocked)})
                except ClientError:
                    pass

                all_acls.append({
                    "Name": acl_summary["Name"],
                    "ARN": acl_summary["ARN"],
                    "Id": acl_summary["Id"],
                    "Scope": "REGIONAL",
                    "Region": region,
                    "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw],
                    "LoggingConfiguration": acl_details.get("LoggingConfiguration", {}),
                    "LoggingDetails": logging_details,
                    "VisibilityConfig": acl_details.get("VisibilityConfig", {}),
                    "TopRules": sorted(top_rules, key=lambda x: x['BlockedRequests'], reverse=True)
                })
        except ClientError:
            pass
        
        # --- 2.5. Collect Regional Web ACLs IDs from WAF Classic ---
        try:
            client_classic_regional = session.client("waf-regional", region_name=region)
            response_classic_regional = client_classic_regional.list_web_acls(Limit=100)
            
            if region not in classic_regional_acls:
                classic_regional_acls[region] = []

            for acl_summary in response_classic_regional.get("WebACLs", []):
                classic_regional_acls[region].append({
                    "Name": f"{acl_summary['Name']} (Classic)",
                    "Id": acl_summary["WebACLId"]
                })
        except ClientError as e:
            pass

    # --- 3. Collect IP Sets (V2 and Classic logic can be added similarly if needed) ---
    # CloudFront (Global) IP Sets
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_ip_sets(Scope="CLOUDFRONT")
        for ip_set_summary in response.get("IPSets", []):
            details = client_global.get_ip_set(Name=ip_set_summary["Name"], Scope="CLOUDFRONT", Id=ip_set_summary["Id"])
            ip_set = details["IPSet"]
            all_ip_sets.append({
                "Name": ip_set["Name"], "ARN": ip_set["ARN"], "Scope": "CLOUDFRONT", "Region": "Global",
                "IPAddressVersion": ip_set["IPAddressVersion"], "AddressCount": len(ip_set["Addresses"])
            })
    except ClientError:
        pass

    # Regional IP Sets
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_ip_sets(Scope="REGIONAL")
            for ip_set_summary in response.get("IPSets", []):
                details = client_regional.get_ip_set(Name=ip_set_summary["Name"], Scope="REGIONAL", Id=ip_set_summary["Id"])
                ip_set = details["IPSet"]
                all_ip_sets.append({
                    "Name": ip_set["Name"], "ARN": ip_set["ARN"], "Scope": "REGIONAL", "Region": region,
                    "IPAddressVersion": ip_set["IPAddressVersion"], "AddressCount": len(ip_set["Addresses"])
                })
        except ClientError:
            pass

    # --- 4. Find and Map WAF Classic Resource Associations ---
    classic_acl_associations = {}
    
    # 4.1. CloudFront Distributions (Global)
    try:
        cf_client = session.client('cloudfront')
        paginator = cf_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            for dist in page.get('DistributionList', {}).get('Items', []):
                web_acl_id = dist.get('WebACLId')
                if web_acl_id:
                    acl_id_clean = web_acl_id.split('/')[-1]
                    if acl_id_clean in [acl['Id'] for acl in classic_global_acls]:
                        if acl_id_clean not in classic_acl_associations:
                            classic_acl_associations[acl_id_clean] = []
                        classic_acl_associations[acl_id_clean].append(dist['ARN'])
    except ClientError:
        pass

    # 4.2. Regional Resources (ALB, API Gateway)
    for region in regions:
        # Application Load Balancers (ALB)
        try:
            elbv2_client = session.client('elbv2', region_name=region)
            waf_regional_client = session.client('waf-regional', region_name=region)
            paginator = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    lb_arn = lb['LoadBalancerArn']
                    try:
                        result = waf_regional_client.get_web_acl_for_resource(ResourceArn=lb_arn)
                        acl_id = result.get('WebACLSummary', {}).get('WebACLId')
                        if acl_id:
                            if acl_id not in classic_acl_associations:
                                classic_acl_associations[acl_id] = []
                            classic_acl_associations[acl_id].append(lb_arn)
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                            continue
        except ClientError:
            pass

        # API Gateway Stages
        try:
            apigw_client = session.client('apigateway', region_name=region)
            account_id = session.client('sts').get_caller_identity()['Account']
            apis = apigw_client.get_rest_apis(limit=500).get('items', [])
            for api in apis:
                api_id = api['id']
                stages = apigw_client.get_stages(restApiId=api_id).get('item', [])
                for stage in stages:
                    stage_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/{stage['stageName']}"
                    web_acl_id = stage.get('webAclArn')
                    if web_acl_id:
                        acl_id_clean = web_acl_id.split('/')[-1]
                        if acl_id_clean in [acl['Id'] for acl in classic_regional_acls.get(region, [])]:
                            if acl_id_clean not in classic_acl_associations:
                                classic_acl_associations[acl_id_clean] = []
                            classic_acl_associations[acl_id_clean].append(stage_arn)
        except ClientError:
            pass

    # --- 5. Final Integration of WAF Classic ACLs with resolved resources ---
    # Globales
    for acl in classic_global_acls:
        associated_resources = classic_acl_associations.get(acl['Id'], [])
        all_acls.append({
            "Name": acl['Name'], "ARN": acl["Id"], "Id": acl["Id"],
            "Scope": "CLOUDFRONT", "Region": "Global",
            "AssociatedResourceArns": [parse_resource_arn(r) for r in associated_resources] if associated_resources else [],
            "LoggingConfiguration": {}, "LoggingDetails": {'all_logging': {'enabled': False}, 'destination_only_logging': {'enabled': False}},
            "VisibilityConfig": {}, "TopRules": [], "Version": "Classic"
        })

    # Regionales
    for region, acls in classic_regional_acls.items():
        for acl in acls:
            associated_resources = classic_acl_associations.get(acl['Id'], [])
            all_acls.append({
                "Name": acl['Name'], "ARN": acl["Id"], "Id": acl["Id"],
                "Scope": "REGIONAL", "Region": region,
                "AssociatedResourceArns": [parse_resource_arn(r) for r in associated_resources] if associated_resources else [],
                "LoggingConfiguration": {}, "LoggingDetails": {'all_logging': {'enabled': False}, 'destination_only_logging': {'enabled': False}},
                "VisibilityConfig": {}, "TopRules": [], "Version": "Classic"
            })
            
    return {"acls": all_acls, "ip_sets": all_ip_sets}

def get_cloudfront_to_waf_map(session):
    """
    Crea un mapa de todas las distribuciones de CloudFront y sus WAFs (v2) asociados.
    Devuelve un diccionario: { "waf_v2_arn": ["cloudfront_dist_arn_1", "cloudfront_dist_arn_2"] }
    """
    cf_to_waf_map = {}
    try:
        cf_client = session.client('cloudfront')
        paginator = cf_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            for dist in page.get('DistributionList', {}).get('Items', []):
                # El campo WebACLId contiene el ARN completo para WAFv2
                web_acl_arn = dist.get('WebACLId', '')
                
                # Nos aseguramos de que es un ARN de WAFv2 (y no un ID de WAF Classic)
                if "arn:aws:wafv2" in web_acl_arn:
                    if web_acl_arn not in cf_to_waf_map:
                        cf_to_waf_map[web_acl_arn] = []
                    cf_to_waf_map[web_acl_arn].append(dist['ARN'])
    except ClientError as e:
        # No es un error fatal, solo no podremos mapear CF
        print(f"[WARN] No se pudieron listar las distribuciones de CloudFront para el mapeo de WAF: {e}")
    return cf_to_waf_map