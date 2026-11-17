# collectors/compute.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


# collectors/compute.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa
from . import iam # Se importa para la comprobación de permisos de roles
from datetime import datetime, timedelta, timezone
from .diagnostics import AWS_ERRORS, classify_error

def collect_compute_data(session):
    """
    Gathers data on key AWS compute resources across all available regions.

    This function scans every AWS region to collect detailed information about
    EC2 instances (including their VPC ID and IAM Instance Profile), 
    Lambda functions (including their tags and execution role), EKS clusters, and ECS clusters.

    Args:
        session (boto3.Session): The Boto3 session object used for AWS 
                                 authentication and to discover all regions.

    Returns:
        dict: A dictionary containing lists of collected resources.
    """
    result_ec2_instances = []
    result_lambda_functions = []
    result_eks_clusters = []
    result_ecs_clusters = []
    
    regions = get_all_aws_regions(session)
    account_id = session.client("sts").get_caller_identity()["Account"]

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            lambda_client = session.client("lambda", region_name=region)
            eks_client = session.client("eks", region_name=region)
            ecs_client = session.client("ecs", region_name=region)

            # --- 1. Collect EC2 Instance Data (sin cambios) ---
            ec2_paginator = ec2_client.get_paginator('describe_instances')
            instance_filters = [{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}]
            
            for page in ec2_paginator.paginate(Filters=instance_filters):
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        tags_dict = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        instance_id = instance.get("InstanceId")
                        
                        iam_profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")
                        iam_profile_name = iam_profile_arn.split('/')[-1] if iam_profile_arn else "N/A"
                        
                        os_info = "N/A"
                        image_id = instance.get("ImageId")
                        if image_id:
                            try:
                                ami_details = ec2_client.describe_images(ImageIds=[image_id])
                                if ami_details.get("Images"):
                                    os_info = ami_details["Images"][0].get("Name", "N/A")
                            except ClientError:
                                os_info = "Information not available"

                        result_ec2_instances.append({
                            "Region": region,
                            "InstanceId": instance_id,
                            "VpcId": instance.get("VpcId"),
                            "InstanceType": instance.get("InstanceType"),
                            "State": instance.get("State", {}).get("Name"),
                            "PublicIpAddress": instance.get("PublicIpAddress", "N/A"),
                            "SubnetId": instance.get("SubnetId"),
                            "SecurityGroups": [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            "IamInstanceProfile": iam_profile_name,
                            "OperatingSystem": os_info,
                            "Tags": tags_dict,
                            "ARN": f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                        })

            # --- 2. Collect Lambda Function Data ---
            lambda_paginator = lambda_client.get_paginator("list_functions")
            region_lambdas = []
            for page in lambda_paginator.paginate():
                for function in page.get("Functions", []):
                    function_arn = function.get("FunctionArn")
                    
                    tags_dict = {}
                    try:
                        tags_response = lambda_client.list_tags(Resource=function_arn)
                        tags_dict = tags_response.get("Tags", {})
                    except ClientError:
                        pass
                    
                    vpc_config = function.get("VpcConfig", {})
                    lambda_record = {
                        "Region": region,
                        "FunctionName": function.get("FunctionName"),
                        "Role": function.get("Role"), # <-- NUEVO CAMPO AÑADIDO
                        "Runtime": function.get("Runtime"),
                        "MemorySize": function.get("MemorySize"),
                        "Timeout": function.get("Timeout"),
                        "LastModified": str(function.get("LastModified")),
                        "VpcConfig": {
                            "VpcId": vpc_config.get("VpcId"),
                            "SubnetIds": vpc_config.get("SubnetIds", []),
                            "SecurityGroupIds": vpc_config.get("SecurityGroupIds", [])
                        },
                        "Tags": tags_dict,
                        "ARN": function_arn
                    }
                    result_lambda_functions.append(lambda_record)
                    region_lambdas.append(lambda_record)

            try:
                cloudwatch_client = session.client("cloudwatch", region_name=region)
                query_functions = {f"f{index}": function for index, function in enumerate(region_lambdas)}
                queries = [{
                    "Id": query_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Invocations",
                            "Dimensions": [{"Name": "FunctionName", "Value": function["FunctionName"]}]
                        },
                        "Period": 86400,
                        "Stat": "Sum"
                    },
                    "ReturnData": True
                } for query_id, function in query_functions.items()]
                metric_results = {}
                for offset in range(0, len(queries), 500):
                    request = {
                        "MetricDataQueries": queries[offset:offset + 500],
                        "StartTime": datetime.now(timezone.utc) - timedelta(days=90),
                        "EndTime": datetime.now(timezone.utc)
                    }
                    while True:
                        response = cloudwatch_client.get_metric_data(**request)
                        for metric_result in response.get("MetricDataResults", []):
                            metric_results.setdefault(metric_result.get("Id"), []).append(metric_result)
                        next_token = response.get("NextToken")
                        if not next_token:
                            break
                        request["NextToken"] = next_token
                for query_id, function in query_functions.items():
                    points = [(timestamp, value) for batch in metric_results.get(query_id, [])
                              for timestamp, value in zip(batch.get("Timestamps", []), batch.get("Values", []))]
                    invocations = sum(value for _, value in points)
                    last_invocation = max((timestamp for timestamp, value in points if value > 0), default=None)
                    function["Invocations90d"] = invocations
                    function["LastInvocationDate"] = last_invocation.date().isoformat() if last_invocation else None
                    function.setdefault("Enrichment", {})["activity"] = {"status": "complete"}
            except AWS_ERRORS as exc:
                reason = classify_error(exc)["category"]
                for function in region_lambdas:
                    function.setdefault("Enrichment", {})["activity"] = {"status": "failed", "reason": reason}

            # --- 3. Recolectar datos de EKS ---
            eks_paginator = eks_client.get_paginator('list_clusters')
            for page in eks_paginator.paginate():
                for cluster_name in page.get('clusters', []):
                    try:
                        cluster_details = eks_client.describe_cluster(name=cluster_name)['cluster']
                        result_eks_clusters.append({
                            "Region": region,
                            "ClusterName": cluster_name,
                            "ARN": cluster_details.get('arn'),
                            "Version": cluster_details.get('version')
                        })
                    except ClientError:
                        continue # Si no se puede describir un cluster, continuamos con el siguiente

            # --- 4. Recolectar datos de ECS ---
            ecs_paginator = ecs_client.get_paginator('list_clusters')
            for page in ecs_paginator.paginate():
                cluster_arns = page.get('clusterArns', [])
                if not cluster_arns:
                    continue
                
                # Describimos los clusters encontrados para obtener más detalles
                described_clusters = ecs_client.describe_clusters(clusters=cluster_arns)['clusters']
                for cluster in described_clusters:
                    result_ecs_clusters.append({
                        "Region": region,
                        "ClusterName": cluster.get('clusterName'),
                        "ARN": cluster.get('clusterArn'),
                        "Status": cluster.get('status'),
                        "ServicesCount": cluster.get('activeServicesCount', 0)
                    })

        except ClientError as e:
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException']
            if e.response['Error']['Code'] not in common_errors:
                print(f"Error processing region {region}: {e}")
            continue
    
    return {
        "ec2_instances": result_ec2_instances,
        "lambda_functions": result_lambda_functions,
        "eks_clusters": result_eks_clusters,
        "ecs_clusters": result_ecs_clusters
    }