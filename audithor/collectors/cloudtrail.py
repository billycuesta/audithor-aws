# collectors/cloudtrail.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import pytz
from .utils import get_all_aws_regions # Importación relativa
from .cloudwatch import get_log_group_destinations


def collect_cloudtrail_data(session: boto3.Session):
    """
    Collects CloudTrail data, including trail configurations and recent events.

    This function performs three main tasks:
    1. Describes all CloudTrail trails in the account, correctly handling
       multi-region trails to avoid duplicates.
    2. Searches for a specific list of security-sensitive API calls across all
       regions from the last 7 days.
    3. Runs a separate analysis function ('run_trailguard_analysis') on the
       collected trail configurations to check for potential issues.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing 'trails', 'events', and 'trailguard_findings'.

    Example:
        >>> import boto3
        >>>
        >>> # Assumes helper functions are available
        >>> aws_session = boto3.Session()
        >>> trail_data = collect_cloudtrail_data(aws_session)
        >>> print(f"Found {len(trail_data['trails'])} CloudTrail trails.")
    """
    regions = get_all_aws_regions(session)
    result_trails = []
    result_events = []
    processed_trail_arns = set()

    # --- 1. Collect Trail Configurations ---
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            # describe_trails in any region can return multi-region trails
            for trail in client.describe_trails().get('trailList', []):
                trail_arn = trail.get("TrailARN")
                if trail_arn not in processed_trail_arns:
                    try:
                        status = client.get_trail_status(Name=trail_arn)
                        result_trails.append({
                            "Name": trail.get("Name"),
                            "HomeRegion": trail.get("HomeRegion"),
                            "S3BucketName": trail.get("S3BucketName"),
                            "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                            "IsOrganizationTrail": trail.get("IsOrganizationTrail", False),
                            "IsLogging": status.get("IsLogging", False),
                            "KmsKeyId": trail.get("KmsKeyId"),
                            "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
                            "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"),
                            "TrailARN": trail_arn
                        })
                        processed_trail_arns.add(trail_arn)
                    except ClientError:
                        continue # Failed to get status, but continue processing other trails
        except ClientError:
            continue # Failed to describe trails in region, continue to next region

    # --- 2. Search for Notable Events (Last 7 Days) ---
    events_to_search = [
        "ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging",
        "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
        "StartInstances", "StopInstances", "TerminateInstances",
        "DisableKey", "ScheduleKeyDeletion"
    ]
    
    end_time = datetime.now(pytz.utc)
    start_time = end_time - timedelta(days=7)

    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for event_name in events_to_search:
                paginator = client.get_paginator('lookup_events')
                page_iterator = paginator.paginate(
                    LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                    StartTime=start_time,
                    EndTime=end_time
                )
                for page in page_iterator:
                    for event in page.get('Events', []):
                        event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        result_events.append({
                            "EventName": event.get("EventName"),
                            "EventTime": str(event.get("EventTime")),
                            "Username": event.get("Username", "N/A"),
                            "EventRegion": event_data.get("awsRegion", region),
                            "SourceIPAddress": event_data.get("sourceIPAddress", "N/A"),
                            "RequestParameters": event_data.get("requestParameters", {})
                        })
        except ClientError:
            continue # Failed to look up events in this region

    # Sort events from most recent to oldest
    result_events.sort(key=lambda x: x['EventTime'], reverse=True)
    
    # --- 3. Run Configuration Analysis ---
    trailguard_findings = run_trailguard_analysis(session, result_trails)
    
    return {
        "trails": result_trails,
        "events": result_events,
        "trailguard_findings": trailguard_findings
    }

def lookup_cloudtrail_events(session, region, event_name, start_time, end_time):
    """
    Searches AWS CloudTrail for specific events within a given time frame and region.

    This function uses a paginator to efficiently retrieve all matching events,
    parses the relevant data from each event, and returns them in a structured format,
    sorted from most recent to oldest.

    Args:
        session (boto3.Session): The Boto3 session object for AWS credentials.
        region (str): The AWS region to perform the search in.
        event_name (str): The name of the event to look for (e.g., 'ConsoleLogin').
        start_time (datetime): The start of the time window for the search.
        end_time (datetime): The end of the time window for the search.

    Returns:
        dict: A dictionary containing a list of found CloudTrail events, sorted
              by time in descending order. Returns {"events": []} if none are found.

    Raises:
        Exception: If there is an API error when communicating with the CloudTrail service.

    Example:
        >>> import boto3
        >>> from datetime import datetime, timedelta
        >>>
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> end_timestamp = datetime.utcnow()
        >>> start_timestamp = end_timestamp - timedelta(days=1)
        >>>
        >>> found_events = lookup_cloudtrail_events(
        ...     session=aws_session,
        ...     region='us-east-1',
        ...     event_name='ConsoleLogin',
        ...     start_time=start_timestamp,
        ...     end_time=end_timestamp
        ... )
    """
    found_events = []
    try:
        client = session.client("cloudtrail", region_name=region)
        paginator = client.get_paginator('lookup_events')
        
        lookup_attributes = []
        if event_name:
            lookup_attributes.append({'AttributeKey': 'EventName', 'AttributeValue': event_name})

        pages = paginator.paginate(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time
        )

        for page in pages:
            for event in page.get('Events', []):
                cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                found_events.append({
                    "EventId": event.get("EventId"),
                    "CloudTrailEvent": event.get('CloudTrailEvent', '{}'),
                    "EventName": event.get("EventName"),
                    "EventTime": str(event.get("EventTime")),
                    "Username": event.get("Username", "N/A"),
                    "EventRegion": cloudtrail_event_data.get("awsRegion", region),
                    "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"),
                    "RequestParameters": cloudtrail_event_data.get("requestParameters", {})
                })

    except ClientError as e:
        # Raise a generic exception so the calling endpoint can catch it and return a clear error.
        raise Exception(f"Error searching for CloudTrail events in region {region}: {str(e)}")

    # Sort events from most recent to oldest before returning
    found_events.sort(key=lambda x: x['EventTime'], reverse=True)
    
    return {"events": found_events}


def run_trailguard_analysis(session, trails_list):
    """
    Analiza CloudTrail configurations para mapear el flujo de datos.
    CORREGIDO: Ahora incluye análisis de EventBridge para eventos de CloudTrail.
    """
    all_trails_flow = []
    
    for trail in trails_list:
        region = trail.get("HomeRegion")
        if not region:
            continue

        flow_data = {
            "TrailName": trail.get("Name"),
            "TrailArn": trail.get("TrailARN"),
            "Region": region,
            "S3Destination": None,
            "CloudWatchDestination": None,
            "EventBridgeFlow": None,
            "DirectCloudTrailEventBridge": None  # NUEVO
        }

        # --- 1. Analyze S3 Destination (código original S3) ---
        if trail.get("S3BucketName"):
            bucket_name = trail["S3BucketName"]
            s3_dest = {"BucketName": bucket_name, "Notifications": []}
            
            try:
                s3_client = session.client("s3", region_name=region)
                notif_config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                
                for config in notif_config.get('LambdaFunctionConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "Lambda", "Target": config.get('LambdaFunctionArn')})
                for config in notif_config.get('QueueConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "SQS", "Target": config.get('QueueArn')})
                for config in notif_config.get('TopicConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "SNS", "Target": config.get('TopicArn')})
            except ClientError:
                pass
            
            flow_data["S3Destination"] = s3_dest
            
            # Verificar EventBridge para S3 (código original)
            eventbridge_config = check_s3_eventbridge_configuration(session, bucket_name, region)
            
            if eventbridge_config["enabled"]:
                eventbridge_rules = find_eventbridge_rules_for_s3_bucket(session, bucket_name, region)
                sns_notifications = []
                for rule in eventbridge_rules:
                    sns_targets = find_sns_targets_in_rule(rule)
                    sns_notifications.extend(sns_targets)
                
                flow_data["EventBridgeFlow"] = {
                    "S3EventBridgeEnabled": True,
                    "Rules": eventbridge_rules,
                    "SNSNotifications": sns_notifications,
                    "CompleteFlow": len(sns_notifications) > 0
                }
            else:
                flow_data["EventBridgeFlow"] = {
                    "S3EventBridgeEnabled": False,
                    "Reason": "EventBridge not enabled for S3 bucket"
                }

        # --- NUEVO: 2. Analyze Direct CloudTrail → EventBridge ---
        print(f"[DEBUG] Checking CloudTrail EventBridge for trail: {trail.get('Name')} in region: {region}")
        cloudtrail_eb_config = check_cloudtrail_eventbridge_configuration(session, trail.get("Name"), region)
        
        if cloudtrail_eb_config["enabled"]:
            cloudtrail_rules = cloudtrail_eb_config.get("rules", [])
            cloudtrail_sns_targets = find_cloudtrail_sns_targets_in_rules(cloudtrail_rules)
            
            flow_data["DirectCloudTrailEventBridge"] = {
                "CloudTrailEventBridgeEnabled": True,
                "Rules": cloudtrail_rules,
                "SNSTargets": cloudtrail_sns_targets,
                "CompleteFlow": len(cloudtrail_sns_targets) > 0,
                "FlowType": "CloudTrail → EventBridge → SNS"
            }
            print(f"[DEBUG] ✓ Found {len(cloudtrail_rules)} CloudTrail EventBridge rules with {len(cloudtrail_sns_targets)} SNS targets")
        else:
            flow_data["DirectCloudTrailEventBridge"] = {
                "CloudTrailEventBridgeEnabled": False,
                "Reason": cloudtrail_eb_config.get("method", "No CloudTrail EventBridge rules found")
            }
            print(f"[DEBUG] ✗ No CloudTrail EventBridge rules found: {cloudtrail_eb_config.get('method')}")

        # --- 3. Analyze CloudWatch Logs Destination (sin cambios) ---
        if trail.get("CloudWatchLogsLogGroupArn"):
            log_group_arn = trail["CloudWatchLogsLogGroupArn"]
            log_group_name = log_group_arn.split(':')[6]
            
            destinations = get_log_group_destinations(session, log_group_arn)
            
            cw_dest = {
                "LogGroupName": log_group_name,
                "Subscriptions": destinations.get("subscriptions", []),
                "MetricFilters": destinations.get("metric_filters", [])
            }
            flow_data["CloudWatchDestination"] = cw_dest
        
        all_trails_flow.append(flow_data)
            
    return all_trails_flow


def check_s3_eventbridge_configuration(session, bucket_name, region):
    """Verifica si EventBridge está habilitado para un bucket S3."""
    try:
        s3_client = session.client("s3", region_name=region)
        notif_config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        
        if 'EventBridgeConfiguration' in notif_config:
            return {"enabled": True, "method": "explicit_configuration"}
        
        return {"enabled": False, "method": "not_configured"}
        
    except ClientError:
        return {"enabled": False, "method": "error"}

def find_eventbridge_rules_for_s3_bucket(session, bucket_name, region):
    """Encuentra reglas de EventBridge que procesan eventos de este bucket específico."""
    try:
        events_client = session.client('events', region_name=region)
        matching_rules = []
        
        paginator = events_client.get_paginator('list_rules')
        for page in paginator.paginate():
            for rule in page.get('Rules', []):
                if rule.get('State') == 'ENABLED':
                    try:
                        rule_detail = events_client.describe_rule(Name=rule['Name'])
                        event_pattern = rule_detail.get('EventPattern')
                        
                        if event_pattern and is_rule_for_specific_s3_bucket(event_pattern, bucket_name):
                            targets_response = events_client.list_targets_by_rule(Rule=rule['Name'])
                            
                            matching_rules.append({
                                "Name": rule['Name'],
                                "EventPattern": event_pattern,
                                "Targets": targets_response.get('Targets', []),
                                "Description": rule_detail.get('Description', ''),
                                # Agregar detalles de SNS
                                "SNSTargets": find_sns_targets_in_rule(
                                    {"Name": rule['Name'], "Targets": targets_response.get('Targets', [])},
                                    session,
                                    region
                                )
                            })
                            
                    except ClientError:
                        continue
        
        return matching_rules
        
    except ClientError:
        return []


def is_rule_for_specific_s3_bucket(event_pattern, bucket_name):
    """Verifica si una regla procesa eventos de un bucket específico."""
    try:
        import json
        pattern = json.loads(event_pattern) if isinstance(event_pattern, str) else event_pattern
        
        # Verificar si es un evento S3
        source = pattern.get('source', [])
        if not ('aws.s3' in source if isinstance(source, list) else source == 'aws.s3'):
            return False
        
        # Verificar si especifica exactamente nuestro bucket
        detail = pattern.get('detail', {})
        if isinstance(detail, dict):
            bucket_info = detail.get('bucket', {})
            if isinstance(bucket_info, dict):
                rule_bucket = bucket_info.get('name')
                
                if isinstance(rule_bucket, list):
                    return bucket_name in rule_bucket
                elif isinstance(rule_bucket, str):
                    return rule_bucket == bucket_name
        
        return False
        
    except (json.JSONDecodeError, Exception):
        return False


def find_sns_targets_in_rule(rule, session=None, region=None):
    """Encuentra targets SNS en una regla de EventBridge con detalles completos."""
    sns_targets = []
    
    for target in rule.get('Targets', []):
        target_arn = target.get('Arn', '')
        if ':sns:' in target_arn:
            sns_target = {
                "TopicArn": target_arn,
                "TargetId": target.get('Id'),
                "RuleName": rule.get('Name')
            }
            
            # Si tenemos sesión y región, obtener detalles completos
            if session and region:
                sns_details = get_sns_topic_details(session, target_arn, region)
                sns_target.update(sns_details)
            
            sns_targets.append(sns_target)
    
    return sns_targets


def check_cloudtrail_eventbridge_configuration(session, trail_name, region):
    """
    Verifica si hay reglas de EventBridge que procesen eventos de CloudTrail.
    MODIFICADO: Busca en todas las regiones y obtiene detalles completos de SNS.
    """
    try:
        # Obtener todas las regiones disponibles
        from .utils import get_all_aws_regions
        all_regions = get_all_aws_regions(session)
        
        print(f"[DEBUG] Searching EventBridge rules for CloudTrail events across ALL regions")
        
        all_cloudtrail_rules = []
        
        # Buscar en todas las regiones
        for search_region in all_regions:
            try:
                events_client = session.client('events', region_name=search_region)
                print(f"[DEBUG] Checking region: {search_region}")
                
                paginator = events_client.get_paginator('list_rules')
                
                for page in paginator.paginate():
                    for rule in page.get('Rules', []):
                        if rule.get('State') == 'ENABLED':
                            try:
                                rule_detail = events_client.describe_rule(Name=rule['Name'])
                                event_pattern = rule_detail.get('EventPattern')
                                
                                if event_pattern and is_rule_for_cloudtrail_events(event_pattern):
                                    targets_response = events_client.list_targets_by_rule(Rule=rule['Name'])
                                    
                                    rule_info = {
                                        "Name": rule['Name'],
                                        "EventPattern": event_pattern,
                                        "Targets": targets_response.get('Targets', []),
                                        "Description": rule_detail.get('Description', ''),
                                        "Arn": rule_detail.get('Arn', ''),
                                        "Region": search_region,
                                        # AGREGAR DETALLES COMPLETOS DE SNS
                                        "SNSTargets": find_sns_targets_in_rule(
                                            {"Name": rule['Name'], "Targets": targets_response.get('Targets', [])},
                                            session,
                                            search_region
                                        )
                                    }
                                    all_cloudtrail_rules.append(rule_info)
                                    
                                    print(f"[DEBUG] ✓ Found CloudTrail rule: {rule['Name']} in region {search_region}")
                                    
                            except ClientError as e:
                                print(f"[DEBUG] Error checking rule {rule['Name']} in {search_region}: {e}")
                                continue
                                
            except ClientError as e:
                print(f"[DEBUG] Error accessing EventBridge in region {search_region}: {e}")
                continue
        
        if all_cloudtrail_rules:
            return {
                "enabled": True, 
                "method": "multi_region_cloudtrail_eventbridge",
                "rules": all_cloudtrail_rules
            }
        else:
            return {
                "enabled": False, 
                "method": "no_cloudtrail_rules_in_any_region"
            }
        
    except Exception as e:
        print(f"[DEBUG] Error in multi-region CloudTrail EventBridge check: {e}")
        return {"enabled": False, "method": "error"}



def is_rule_for_cloudtrail_events(event_pattern):
    """
    Verifica si una regla procesa eventos de CloudTrail.
    """
    try:
        import json
        
        # Parsear el event pattern si es string
        if isinstance(event_pattern, str):
            pattern = json.loads(event_pattern)
        else:
            pattern = event_pattern
            
        print(f"[DEBUG] Checking CloudTrail pattern: {pattern}")
        
        # 1. Verificar si es un evento de CloudTrail
        source = pattern.get('source', [])
        if isinstance(source, list):
            is_cloudtrail_event = 'aws.cloudtrail' in source
        else:
            is_cloudtrail_event = source == 'aws.cloudtrail'
            
        if not is_cloudtrail_event:
            print(f"[DEBUG] Not a CloudTrail event. Source: {source}")
            return False
        
        # 2. Verificar detail-type para CloudTrail
        detail_type = pattern.get('detail-type', [])
        if isinstance(detail_type, list):
            has_cloudtrail_detail = 'AWS API Call via CloudTrail' in detail_type
        else:
            has_cloudtrail_detail = detail_type == 'AWS API Call via CloudTrail'
            
        print(f"[DEBUG] CloudTrail event: {is_cloudtrail_event}, Has detail-type: {has_cloudtrail_detail}")
        
        return is_cloudtrail_event and has_cloudtrail_detail
        
    except (json.JSONDecodeError, Exception) as e:
        print(f"[DEBUG] Error parsing CloudTrail event pattern: {e}")
        return False

def find_cloudtrail_sns_targets_in_rules(rules):
    """
    Encuentra targets SNS en reglas de EventBridge para CloudTrail.
    """
    sns_targets = []
    
    for rule in rules:
        rule_name = rule.get('Name', 'Unknown')
        for target in rule.get('Targets', []):
            target_arn = target.get('Arn', '')
            if ':sns:' in target_arn:
                sns_targets.append({
                    "TopicArn": target_arn,
                    "TargetId": target.get('Id'),
                    "RuleName": rule_name
                })
    
    return sns_targets


def get_sns_topic_details(session, topic_arn, region):
    """
    Obtiene los detalles completos de un topic SNS incluyendo subscripciones.
    """
    try:
        sns_client = session.client('sns', region_name=region)
        
        topic_name = topic_arn.split(':')[-1]
        
        # Obtener subscriptions del topic
        subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        subscriptions = subscriptions_response.get('Subscriptions', [])
        
        # Obtener atributos del topic
        topic_attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
        display_name = topic_attrs.get('Attributes', {}).get('DisplayName', topic_name)
        
        # Formatear subscriptions
        formatted_subscriptions = []
        for sub in subscriptions:
            protocol = sub.get('Protocol', '')
            endpoint = sub.get('Endpoint', '')
            status = sub.get('SubscriptionArn', 'PendingConfirmation')
            
            formatted_subscriptions.append({
                'Protocol': protocol,
                'Endpoint': endpoint,
                'Status': 'Confirmed' if status.startswith('arn:') else 'Pending'
            })
        
        return {
            'TopicArn': topic_arn,
            'TopicName': topic_name,
            'DisplayName': display_name,
            'Subscriptions': formatted_subscriptions,
            'SubscriptionCount': len(formatted_subscriptions)
        }
        
    except ClientError as e:
        return {
            'TopicArn': topic_arn,
            'TopicName': topic_arn.split(':')[-1],
            'DisplayName': topic_arn.split(':')[-1],
            'Subscriptions': [],
            'SubscriptionCount': 0,
            'Error': f'Could not retrieve topic details: {str(e)}'
        }