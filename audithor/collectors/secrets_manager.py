# collectors/secrets_manager.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

def collect_secrets_manager_data(session):
    """
    Gathers detailed information about AWS Secrets Manager secrets across all regions.
    
    This function collects comprehensive data about secrets including metadata,
    rotation configuration, resource policies, and security analysis for audit purposes.
    
    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication
        
    Returns:
        dict: A dictionary containing secrets data organized by region with security analysis
    """
    all_regions = get_all_aws_regions(session)
    result_secrets = []
    
    for region in all_regions:
        try:
            secrets_client = session.client("secretsmanager", region_name=region)
            
            # List all secrets in the region
            paginator = secrets_client.get_paginator("list_secrets")
            
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    secret_arn = secret["ARN"]
                    
                    try:
                        # Get detailed secret information
                        secret_details = secrets_client.describe_secret(SecretId=secret_arn)
                        
                        # Get resource policy if exists
                        resource_policy = None
                        try:
                            policy_response = secrets_client.get_resource_policy(SecretId=secret_arn)
                            resource_policy = json.loads(policy_response.get("ResourcePolicy", "{}"))
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                                resource_policy = f"Error retrieving policy: {e.response['Error']['Code']}"
                        
                        # Analyze rotation configuration
                        rotation_config = analyze_rotation_config(secret_details)
                        
                        # Security analysis
                        security_issues = analyze_secret_security(secret_details, resource_policy)
                        
                        result_secrets.append({
                            "Region": region,
                            "Name": secret_details.get("Name"),
                            "ARN": secret_arn,
                            "Description": secret_details.get("Description", "No description"),
                            "KmsKeyId": secret_details.get("KmsKeyId", "Default AWS managed key"),
                            "RotationEnabled": secret_details.get("RotationEnabled", False),
                            "RotationLambdaARN": secret_details.get("RotationLambdaARN"),
                            "RotationRules": secret_details.get("RotationRules", {}),
                            "LastRotatedDate": secret_details.get("LastRotatedDate"),
                            "LastChangedDate": secret_details.get("LastChangedDate"),
                            "LastAccessedDate": secret_details.get("LastAccessedDate"),
                            "DeletedDate": secret_details.get("DeletedDate"),
                            "Tags": secret_details.get("Tags", []),
                            "SecretVersionsToStages": secret_details.get("SecretVersionsToStages", {}),
                            "OwningService": secret_details.get("OwningService"),
                            "CreatedDate": secret_details.get("CreatedDate"),
                            "PrimaryRegion": secret_details.get("PrimaryRegion"),
                            "ReplicationStatus": secret_details.get("ReplicationStatus", []),
                            "ResourcePolicy": resource_policy,
                            "RotationAnalysis": rotation_config,
                            "SecurityIssues": security_issues,
                            "RiskScore": calculate_risk_score(secret_details, resource_policy, security_issues)
                        })
                        
                    except ClientError as e:
                        # Log individual secret errors but continue
                        result_secrets.append({
                            "Region": region,
                            "Name": secret.get("Name", "Unknown"),
                            "ARN": secret_arn,
                            "Error": f"Failed to retrieve details: {e.response['Error']['Code']}"
                        })
                        
        except ClientError as e:
            # Skip regions that are not accessible or enabled
            common_errors = [
                'InvalidClientTokenId', 'UnrecognizedClientException', 
                'AuthFailure', 'AccessDeniedException', 'OptInRequired'
            ]
            if e.response['Error']['Code'] in common_errors:
                continue
        except Exception:
            # Continue with other regions if unexpected error occurs
            continue
    
    return {"secrets": result_secrets}

def analyze_rotation_config(secret_details):
    """Analyze secret rotation configuration for security best practices."""
    analysis = {
        "status": "Not Configured",
        "issues": [],
        "recommendations": []
    }
    
    rotation_enabled = secret_details.get("RotationEnabled", False)
    rotation_lambda = secret_details.get("RotationLambdaARN")
    rotation_rules = secret_details.get("RotationRules", {})
    last_rotated = secret_details.get("LastRotatedDate")
    
    if not rotation_enabled:
        analysis["status"] = "Disabled"
        analysis["issues"].append("Automatic rotation is not enabled")
        analysis["recommendations"].append("Enable automatic rotation for enhanced security")
    else:
        analysis["status"] = "Enabled"
        
        if not rotation_lambda:
            analysis["issues"].append("No rotation Lambda function configured")
            
        if rotation_rules:
            interval = rotation_rules.get("AutomaticallyAfterDays", 0)
            if interval > 90:
                analysis["issues"].append(f"Rotation interval ({interval} days) exceeds recommended 90 days")
            elif interval < 30:
                analysis["recommendations"].append("Consider if rotation interval is too frequent for operational needs")
        
        if last_rotated:
            import datetime
            from datetime import timezone
            now = datetime.datetime.now(timezone.utc)
            if isinstance(last_rotated, datetime.datetime):
                days_since_rotation = (now - last_rotated).days
                if days_since_rotation > 365:
                    analysis["issues"].append(f"Secret has not been rotated for {days_since_rotation} days")
    
    return analysis

def analyze_secret_security(secret_details, resource_policy):
    """Analyze secret for potential security issues."""
    issues = []
    
    # Check KMS key usage
    kms_key = secret_details.get("KmsKeyId")
    if not kms_key or kms_key.startswith("alias/aws/secretsmanager"):
        issues.append({
            "type": "encryption",
            "severity": "medium",
            "description": "Using AWS managed KMS key instead of customer managed key",
            "recommendation": "Consider using a customer managed KMS key for enhanced control"
        })
    
    # Check resource policy for overly permissive access
    if resource_policy and isinstance(resource_policy, dict):
        for statement in resource_policy.get("Statement", []):
            principal = statement.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                issues.append({
                    "type": "access_control",
                    "severity": "high",
                    "description": "Resource policy allows public access via wildcard principal",
                    "recommendation": "Restrict access to specific principals or roles"
                })
    
    # Check for missing tags
    tags = secret_details.get("Tags", [])
    if not tags:
        issues.append({
            "type": "governance",
            "severity": "low", 
            "description": "Secret has no tags for governance and cost tracking",
            "recommendation": "Add appropriate tags for environment, owner, and purpose"
        })
    
    # Check description
    description = secret_details.get("Description", "")
    if not description or description == "No description":
        issues.append({
            "type": "documentation",
            "severity": "low",
            "description": "Secret lacks a description",
            "recommendation": "Add a clear description explaining the secret's purpose"
        })
    
    # Check for replication
    replication_status = secret_details.get("ReplicationStatus", [])
    if not replication_status:
        issues.append({
            "type": "availability",
            "severity": "medium",
            "description": "Secret is not replicated to other regions",
            "recommendation": "Consider replicating critical secrets for disaster recovery"
        })
    
    return issues

def calculate_risk_score(secret_details, resource_policy, security_issues):
    """Calculate a risk score for the secret based on various factors."""
    score = 0
    
    # Base score for having a secret
    score += 10
    
    # Add points for security issues
    for issue in security_issues:
        severity = issue.get("severity", "low")
        if severity == "high":
            score += 25
        elif severity == "medium":
            score += 15
        elif severity == "low":
            score += 5
    
    # Reduce score for good practices
    if secret_details.get("RotationEnabled"):
        score -= 10
    
    if secret_details.get("KmsKeyId") and not secret_details.get("KmsKeyId").startswith("alias/aws/"):
        score -= 5
    
    if secret_details.get("Tags"):
        score -= 5
    
    if secret_details.get("ReplicationStatus"):
        score -= 5
    
    # Ensure score is within bounds
    return max(0, min(100, score))