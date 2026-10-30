# collectors/cloudwatch.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_cloudwatch_data(session):
    """
    Collects CloudWatch alarms and SNS topics from all available AWS regions.

    This function iterates through every AWS region accessible by the provided
    credentials. For each region, it retrieves all CloudWatch metric alarms and
    all SNS topics that have confirmed email subscriptions. It gracefully skips
    regions that are not enabled for the account.

    Args:
        session (boto3.Session): The main Boto3 session object used to
                                 derive credentials and discover regions.

    Returns:
        dict: A dictionary with two keys:
              - 'alarms': A list of CloudWatch alarm configuration dictionaries.
              - 'topics': A list of SNS topics that have email subscriptions.

    Example:
        >>> import boto3
        >>>
        >>> # This assumes 'get_all_aws_regions' is an available function
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> all_data = collect_cloudwatch_data(aws_session)
        >>> print(f"Found {len(all_data['alarms'])} alarms across all regions.")
        >>> print(f"Found {len(all_data['topics'])} topics with email subs.")
    """
    all_regions = get_all_aws_regions(session)
    result_alarms = []
    result_topics = []

    for region in all_regions:
        try:
            # Create a new session for each specific region
            session_regional = boto3.Session(
                aws_access_key_id=session.get_credentials().access_key,
                aws_secret_access_key=session.get_credentials().secret_key,
                aws_session_token=session.get_credentials().token,
                region_name=region
            )
            cw_client = session_regional.client("cloudwatch")
            sns_client = session_regional.client("sns")

            # 1. Collect CloudWatch Alarms
            try:
                paginator_alarms = cw_client.get_paginator('describe_alarms')
                for page in paginator_alarms.paginate():
                    for alarm in page.get('MetricAlarms', []):
                        alarm['Region'] = region
                        result_alarms.append(alarm)
            except ClientError as e:
                if "OptInRequired" in str(e):
                    continue # Skip regions that are not enabled

            # 2. Collect SNS Topics and their email subscriptions
            try:
                paginator_topics = sns_client.get_paginator('list_topics')
                all_topics_in_region = []
                for page in paginator_topics.paginate():
                    all_topics_in_region.extend(page.get("Topics", []))

                for topic in all_topics_in_region:
                    topic_arn = topic['TopicArn']
                    subscriptions = []
                    try:
                        paginator_subs = sns_client.get_paginator('list_subscriptions_by_topic')
                        for page in paginator_subs.paginate(TopicArn=topic_arn):
                            for sub in page.get("Subscriptions", []):
                                is_email = sub.get("Protocol") in ["email", "email-json"]
                                is_confirmed = sub.get("SubscriptionArn") != "PendingConfirmation"
                                if is_email and is_confirmed:
                                    subscriptions.append({
                                        "Endpoint": sub.get("Endpoint"),
                                        "Protocol": sub.get("Protocol")
                                    })
                    except ClientError:
                        # Ignore errors for specific topics (e.g., permissions) and continue
                        pass
                    
                    if subscriptions:
                        result_topics.append({
                            "TopicArn": topic_arn,
                            "Region": region,
                            "Subscriptions": subscriptions
                        })
            except ClientError as e:
                if "OptInRequired" in str(e):
                    continue # Skip regions that are not enabled

        except ClientError as e:
            # Catch broader errors for regions that cannot be accessed
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e):
                continue

    return {"alarms": result_alarms, "topics": result_topics}


def get_log_group_destinations(session, log_group_arn):
    """
    Inspects a CloudWatch Log Group to find all its downstream consumers.

    This function identifies two types of destinations for a log group's data:
    1. Subscription Filters: Direct data streams to services like Lambda, Kinesis, etc.
    2. Metric Filters: Rules that create CloudWatch Metrics from log data, including
       any CloudWatch Alarms configured to watch those metrics.
    """
    destinations = {
        "subscriptions": [],
        "metric_filters": []
    }
    try:
        log_region = log_group_arn.split(':')[3]
        log_group_name = log_group_arn.split(':')[6]
        logs_client = session.client("logs", region_name=log_region)
        cw_client = session.client("cloudwatch", region_name=log_region)

        # --- 1. Get Subscription Filters (Data Streams) ---
        subs = logs_client.describe_subscription_filters(logGroupName=log_group_name)
        for sub in subs.get('subscriptionFilters', []):
            dest_arn = sub.get('destinationArn', '')
            service_type = "Unknown"
            if "lambda" in dest_arn: service_type = "Lambda"
            elif "kinesis" in dest_arn: service_type = "Kinesis"
            elif "firehose" in dest_arn: service_type = "Firehose"
            elif "opensearch" in dest_arn: service_type = "OpenSearch"
            
            destinations["subscriptions"].append({
                "Type": service_type,
                "Target": dest_arn
            })

        # --- 2. Get Metric Filters and their associated Alarms ---
        metric_filters = logs_client.describe_metric_filters(logGroupName=log_group_name)
        for mf in metric_filters.get('metricFilters', []):
            metric_transformation = mf.get('metricTransformations', [{}])[0]
            mf_data = {
                "FilterName": mf.get('filterName'),
                "MetricName": metric_transformation.get('metricName'),
                "Namespace": metric_transformation.get('metricNamespace'),
                "Alarms": []
            }
            
            # If the filter defines a valid metric, check for alarms on it
            if mf_data["MetricName"] and mf_data["Namespace"]:
                # CORREGIDO: Usar describe_alarms en lugar de describe_alarms_for_metric
                try:
                    # Obtener todas las alarmas y filtrar las que coincidan con nuestra métrica
                    paginator = cw_client.get_paginator('describe_alarms')
                    for page in paginator.paginate():
                        for alarm in page.get('MetricAlarms', []):
                            # Verificar si esta alarma usa nuestra métrica
                            if (alarm.get('MetricName') == mf_data["MetricName"] and 
                                alarm.get('Namespace') == mf_data["Namespace"]):
                                
                                alarm_name = alarm.get('AlarmName')
                                
                                # DEBUG: Imprimir información de la alarma
                                print(f"Found alarm: {alarm_name}")
                                print(f"  AlarmActions: {alarm.get('AlarmActions', [])}")
                                print(f"  OKActions: {alarm.get('OKActions', [])}")
                                print(f"  InsufficientDataActions: {alarm.get('InsufficientDataActions', [])}")
                                
                                # Obtener detalles de SNS para cada alarma
                                sns_details = get_alarm_sns_details(session, alarm_name, log_region)
                                
                                alarm_data = {
                                    "AlarmName": alarm_name,
                                    "AlarmDescription": alarm.get('AlarmDescription', ''),
                                    "State": alarm.get('StateValue', 'UNKNOWN'),
                                    "SNSTopics": sns_details or []
                                }
                                
                                mf_data["Alarms"].append(alarm_data)
                                
                except ClientError as e:
                    print(f"Error getting alarms for metric {mf_data['MetricName']}: {str(e)}")
                    pass
            
            destinations["metric_filters"].append(mf_data)

    except (ClientError, IndexError) as e:
        print(f"Error in get_log_group_destinations: {str(e)}")  # Debug
        pass
        
    return destinations


def get_alarm_sns_details(session, alarm_name, region):
    """
    Obtiene los detalles completos de SNS para una alarma específica.
    Incluye topics y sus subscriptions (emails, etc.)
    """
    try:
        cloudwatch_client = session.client('cloudwatch', region_name=region)
        sns_client = session.client('sns', region_name=region)
        
        # Obtener detalles de la alarma - USAR describe_alarms en lugar de describe_alarms_for_metric
        alarms = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
        if not alarms.get('MetricAlarms'):
            return None
        
        alarm = alarms['MetricAlarms'][0]
        
        # CORREGIDO: Obtener todas las acciones SNS (AlarmActions, OKActions, InsufficientDataActions)
        all_actions = []
        all_actions.extend(alarm.get('AlarmActions', []))
        all_actions.extend(alarm.get('OKActions', []))
        all_actions.extend(alarm.get('InsufficientDataActions', []))
        
        sns_details = []
        
        for action_arn in all_actions:
            if ':sns:' in action_arn:
                # Es un topic SNS
                topic_name = action_arn.split(':')[-1]
                
                try:
                    # Obtener subscriptions del topic
                    subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=action_arn)
                    subscriptions = subscriptions_response.get('Subscriptions', [])
                    
                    # Obtener atributos del topic
                    topic_attrs = sns_client.get_topic_attributes(TopicArn=action_arn)
                    display_name = topic_attrs.get('Attributes', {}).get('DisplayName', topic_name)
                    
                    # Formatear subscriptions
                    formatted_subscriptions = []
                    for sub in subscriptions:
                        protocol = sub.get('Protocol', '')
                        endpoint = sub.get('Endpoint', '')
                        status = sub.get('SubscriptionArn', 'PendingConfirmation')
                        
                        # NO enmascarar emails para debugging - puedes cambiar esto después
                        # if protocol == 'email' and '@' in endpoint:
                        #     parts = endpoint.split('@')
                        #     masked_email = f"{parts[0][:2]}***@{parts[1]}"
                        #     endpoint = masked_email
                        
                        formatted_subscriptions.append({
                            'Protocol': protocol,
                            'Endpoint': endpoint,
                            'Status': 'Confirmed' if status.startswith('arn:') else 'Pending'
                        })
                    
                    sns_details.append({
                        'TopicArn': action_arn,
                        'TopicName': topic_name,
                        'DisplayName': display_name,
                        'Subscriptions': formatted_subscriptions,
                        'SubscriptionCount': len(formatted_subscriptions)
                    })
                    
                except ClientError as e:
                    # Si no podemos obtener detalles del topic, al menos registramos que existe
                    sns_details.append({
                        'TopicArn': action_arn,
                        'TopicName': topic_name,
                        'DisplayName': topic_name,
                        'Subscriptions': [],
                        'SubscriptionCount': 0,
                        'Error': f'Could not retrieve topic details: {str(e)}'
                    })
        
        return sns_details if sns_details else None
        
    except ClientError as e:
        print(f"Error getting alarm SNS details for {alarm_name}: {str(e)}")  # Debug
        return None
