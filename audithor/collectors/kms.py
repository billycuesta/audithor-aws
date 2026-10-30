# collectors/kms.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_kms_data(session):
    """
    Gathers detailed information about all AWS KMS keys across every region.

    This function iterates through all available AWS regions to create a
    comprehensive inventory of KMS keys. For each key, it collects metadata,
    all associated aliases, its rotation status (for customer-managed keys),
    and its resource policy.

    Args:
        session (boto3.Session): The Boto3 session object for AWS 
                                 authentication and to discover all regions.

    Returns:
        dict: A dictionary containing a single key, 'keys', which holds a list 
              of dictionaries. Each inner dictionary represents one KMS key.

    Example:
        >>> import boto3
        >>>
        >>> # This assumes 'get_all_aws_regions' is an available function
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> kms_inventory = collect_kms_data(aws_session)
        >>> print(f"Found {len(kms_inventory['keys'])} KMS keys in total.")
    """
    all_regions = get_all_aws_regions(session)
    result_kms_keys = []

    for region in all_regions:
        try:
            kms_client = session.client("kms", region_name=region)

            # --- 1. Build a map of Key IDs to all their Aliases ---
            alias_map = {}
            aliases_paginator = kms_client.get_paginator("list_aliases")
            for page in aliases_paginator.paginate():
                for alias in page.get("Aliases", []):
                    if 'TargetKeyId' in alias:
                        key_id = alias['TargetKeyId']
                        if key_id not in alias_map:
                            alias_map[key_id] = []
                        alias_map[key_id].append(alias['AliasName'])

            # --- 2. List all keys and describe each one in detail ---
            keys_paginator = kms_client.get_paginator("list_keys")
            for page in keys_paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key['KeyId']
                    desc = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
                    
                    # --- Check rotation status for applicable keys ---
                    rotation_enabled = "N/A" # Default for AWS managed or asymmetric keys
                    is_customer_symmetric = (desc.get('KeyManager') == 'CUSTOMER' and 
                                             desc.get('KeySpec') == 'SYMMETRIC_DEFAULT')
                    if is_customer_symmetric:
                        try:
                            status = kms_client.get_key_rotation_status(KeyId=key_id)
                            rotation_enabled = "Enabled" if status.get('KeyRotationEnabled') else "Disabled"
                        except ClientError:
                            # Some keys might not support this call
                            rotation_enabled = "Not Supported"
                    
                    # --- Retrieve and parse the key policy ---
                    policy_doc = "Could not retrieve"
                    try:
                        policy_str = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
                        policy_doc = json.loads(policy_str)
                    except (ClientError, json.JSONDecodeError):
                        # Gracefully fail if policy is inaccessible or malformed
                        pass

                    result_kms_keys.append({
                        "Region": region,
                        "KeyId": key_id,
                        "ARN": desc.get('Arn'),
                        "Aliases": ", ".join(alias_map.get(key_id, ["(No Alias)"])),
                        "Status": desc.get('KeyState'),
                        "Origin": desc.get('Origin'),
                        "KeyManager": desc.get('KeyManager'),
                        "RotationEnabled": rotation_enabled,
                        "Policy": policy_doc,
                    })
        except ClientError as e:
            # Ignore common errors for disabled or inaccessible regions
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] in common_errors:
                continue
        except Exception:
            # Catch any other unexpected error and continue
            continue
            
    return {"keys": result_kms_keys}

