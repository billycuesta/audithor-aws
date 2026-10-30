# collectors/ecr.py
import json
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

def collect_ecr_data(session):
    """
    Collects security-related details for all ECR repositories across all regions.

    This function iterates through each AWS region to gather information on ECR
    repositories. For each repository, it checks:
    - Image tag mutability status.
    - Image scanning configuration (scan on push).
    - Encryption settings (AES256 or KMS).
    - The repository policy, specifically checking for public access.
    - Any configured lifecycle policies.
    - Image signing configuration via Signer profiles.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing a single key, 'repositories', which holds a
              list of dictionaries, each representing an ECR repository with its
              security configurations.
    """
    all_repositories = []
    all_regions = get_all_aws_regions(session)

    for region in all_regions:
        try:
            ecr_client = session.client('ecr', region_name=region)
            signer_client = session.client('signer', region_name=region)
            paginator = ecr_client.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    repo_name = repo.get('repositoryName')
                    
                    # 1. Check for public access in the repository policy
                    is_public = False
                    policy_text = None
                    try:
                        policy_response = ecr_client.get_repository_policy(repositoryName=repo_name)
                        policy_text = json.loads(policy_response.get('policyText', '{}'))
                        statements = policy_text.get('Statement', [])
                        for stmt in statements:
                            if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                                is_public = True
                                break
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'RepositoryPolicyNotFoundException':
                            raise # Relaunch other errors
                    
                    # 2. Check for lifecycle policy
                    lifecycle_policy_text = None
                    try:
                        lifecycle_response = ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                        lifecycle_policy_text = json.loads(lifecycle_response.get('lifecyclePolicyText', '{}'))
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'LifecyclePolicyNotFoundException':
                            raise
                    
                    # 3. Check for image signing configuration
                    image_signing_enabled = False
                    signing_profile_name = None
                    signing_profile_version = None
                    
                    try:
                        # Get signing profiles and check if any are associated with this repository
                        signing_profiles_response = signer_client.list_signing_profiles(
                            platformId='Notation-OCI-SHA384-ECDSA'  # ECR uses this platform
                        )
                        
                        for profile in signing_profiles_response.get('profiles', []):
                            profile_name = profile.get('profileName')
                            
                            # Check if this signing profile is used with ECR
                            try:
                                # Try to get signing profile details
                                profile_details = signer_client.describe_signing_job(
                                    jobId=profile.get('profileVersion', 'latest')
                                )
                                
                                # If we find any signing profile configured for ECR platform, 
                                # we consider signing potentially enabled for this repository
                                if profile_name:
                                    image_signing_enabled = True
                                    signing_profile_name = profile_name
                                    signing_profile_version = profile.get('profileVersion')
                                    break
                                    
                            except ClientError:
                                # Continue checking other profiles
                                continue
                                
                    except ClientError as e:
                        # Signer service might not be available in some regions or accounts
                        # This is not an error, just means signing is not configured
                        pass
                    
                    # Alternative approach: Check for trust policies that might indicate signing
                    # ECR repositories with signing often have specific trust policies
                    has_signing_trust_policy = False
                    if policy_text and policy_text.get('Statement'):
                        for stmt in policy_text.get('Statement', []):
                            conditions = stmt.get('Condition', {})
                            # Look for conditions that typically indicate signing requirements
                            if any('aws:PrincipalTag/signer' in str(condition) or 
                                   'ecr:image-signing' in str(condition) for condition in conditions.values() if isinstance(conditions.values(), (list, dict))):
                                has_signing_trust_policy = True
                                break

                    all_repositories.append({
                        "Region": region,
                        "RepositoryName": repo_name,
                        "RepositoryArn": repo.get('repositoryArn'),
                        "ImageTagMutability": repo.get('imageTagMutability'),
                        "ScanOnPush": repo.get('imageScanningConfiguration', {}).get('scanOnPush', False),
                        "EncryptionType": repo.get('encryptionConfiguration', {}).get('encryptionType'),
                        "KmsKey": repo.get('encryptionConfiguration', {}).get('kmsKey'),
                        "IsPublic": is_public,
                        "Policy": policy_text,
                        "LifecyclePolicy": lifecycle_policy_text,
                        "HasLifecyclePolicy": lifecycle_policy_text is not None,
                        "ImageSigningEnabled": image_signing_enabled,
                        "SigningProfileName": signing_profile_name,
                        "SigningProfileVersion": signing_profile_version,
                        "HasSigningTrustPolicy": has_signing_trust_policy
                    })
        except ClientError:
            # Ignore regions where ECR might not be available or enabled
            continue
            
    return {"repositories": all_repositories}