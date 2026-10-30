import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions  # Relative import


def detect_privileges(users, roles, groups, session):
    """
    Analyzes IAM entities to flag them as privileged based on attached policies.

    This function modifies the user, role, and group dictionaries in place,
    adding 'IsPrivileged' and 'PrivilegeReasons' keys if they have any
    policies from a predefined list of dangerous policies.

    Args:
        users (list): A list of IAM user dictionaries.
        roles (list): A list of IAM role dictionaries.
        groups (list): A list of IAM group dictionaries.
        session (boto3.Session): The boto3 session for creating IAM clients.

    Returns:
        None: The input lists are modified directly.

    Example:
        >>> detect_privileges(user_list, role_list, group_list, session)
    """
    client = session.client("iam")
    dangerous_policies = [
        "AdministratorAccess", "PowerUserAccess", "IAMFullAccess", "Billing",
        "OrganizationAccountAccessRole", "AWSCloudFormationFullAccess", "AmazonEC2FullAccess",
        "AWSLambda_FullAccess", "SecretsManagerReadWrite", "AWSKeyManagementServicePowerUser",
        "AmazonS3FullAccess", "AWSCloudTrail_FullAccess", "ServiceQuotasFullAccess"
    ]

    for user in users:
        evidence = [f"Attached Policy: {p}" for p in user["AttachedPolicies"] if p in dangerous_policies]
        for group_name in user["Groups"]:
            try:
                group_policies = client.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
                evidence.extend(f"Group '{group_name}': Policy {gp['PolicyName']}" for gp in group_policies if gp["PolicyName"] in dangerous_policies)
            except client.exceptions.NoSuchEntityException:
                continue
        if evidence:
            user["IsPrivileged"], user["PrivilegeReasons"] = True, list(set(evidence))

    for role in roles:
        evidence = [f"Attached Policy: {p}" for p in role["AttachedPolicies"] if p in dangerous_policies]
        if evidence:
            role["IsPrivileged"], role["PrivilegeReasons"] = True, list(set(evidence))

    for group in groups:
        evidence = [f"Attached Policy: {p}" for p in group["AttachedPolicies"] if p in dangerous_policies]
        if evidence:
            group["IsPrivileged"], group["PrivilegeReasons"] = True, list(set(evidence))


def collect_iam_data(session):
    """
    Versión optimizada que NO obtiene roles asumibles durante el escaneo inicial.
    Solo mantiene la funcionalidad de roles por tags.
    Ahora incluye verificación del MFA del usuario root.
    """
    client = session.client("iam")
    result_users, password_policy, result_roles, result_groups = [], {}, [], []
    users = client.list_users()["Users"]

    for user in users:
        username = user["UserName"]
        user_data = {
            "UserName": username,
            "CreateDate": str(user.get("CreateDate")),
            "PasswordEnabled": False,
            "PasswordLastUsed": str(user.get("PasswordLastUsed")) if user.get("PasswordLastUsed") else "N/A",
            "MFADevices": [m["SerialNumber"] for m in client.list_mfa_devices(UserName=username)["MFADevices"]],
            "AccessKeys": [],
            "Groups": [g["GroupName"] for g in client.list_groups_for_user(UserName=username)["Groups"]],
            "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_user_policies(UserName=username)["AttachedPolicies"]],
            "InlinePolicies": client.list_user_policies(UserName=username)["PolicyNames"],
            "Roles": [],  # Solo roles por tags
            "IsPrivileged": False, 
            "PrivilegeReasons": []
        }
        
        # Verificar password habilitado
        try:
            client.get_login_profile(UserName=username)
            user_data["PasswordEnabled"] = True
        except client.exceptions.NoSuchEntityException:
            pass
            
        # Obtener access keys
        for key in client.list_access_keys(UserName=username)["AccessKeyMetadata"]:
            last_used_info = client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
            user_data["AccessKeys"].append({
                "AccessKeyId": key["AccessKeyId"], 
                "Status": key["Status"], 
                "CreateDate": str(key["CreateDate"]),
                "LastUsedDate": str(last_used_info.get("LastUsedDate")) if last_used_info.get("LastUsedDate") else "N/A"
            })
        
        # SOLO roles por tags (rápido)
        try:
            for tag in client.list_user_tags(UserName=username)["Tags"]:
                if tag['Key'].lower() == 'role':
                    user_data["Roles"].append({
                        'RoleName': tag['Value'],
                        'Source': 'Tag-based'
                    })
        except client.exceptions.NoSuchEntityException:
            pass
        
        result_users.append(user_data)

    # Obtener política de contraseñas
    try:
        password_policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        password_policy = {"Error": "No password policy configured"}

    # NUEVA FUNCIONALIDAD: Verificar MFA del usuario root
    root_mfa_status = check_root_mfa_status(session)
    password_policy["RootMFAStatus"] = root_mfa_status

    # Resto del código igual...
    for role in client.list_roles()["Roles"]:
        result_roles.append({
            "RoleName": role["RoleName"], 
            "CreateDate": str(role["CreateDate"]),
            "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]],
            "InlinePolicies": client.list_role_policies(RoleName=role["RoleName"])["PolicyNames"],
            "IsPrivileged": False, 
            "PrivilegeReasons": []
        })

    for group in client.list_groups()["Groups"]:
        result_groups.append({
            "GroupName": group["GroupName"], 
            "CreateDate": str(group["CreateDate"]),
            "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]],
            "IsPrivileged": False, 
            "PrivilegeReasons": []
        })

    detect_privileges(result_users, result_roles, result_groups, session)
    result_users = check_mfa_compliance_for_cli(session, result_users)
    return {"users": result_users, "roles": result_roles, "groups": result_groups, "password_policy": password_policy}


def get_user_assumable_roles(session, username):
    """
    Nueva función que obtiene roles asumibles para UN usuario específico.
    Se llama bajo demanda desde el frontend.
    
    Args:
        session (boto3.Session): The boto3 session for creating clients.
        username (str): Nombre del usuario específico
        
    Returns:
        dict: Información de roles asumibles para el usuario
    """
    client = session.client("iam")
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    
    try:
        # Obtener roles asumibles para este usuario específico
        assumable_roles = get_assumable_roles_for_user(client, username, account_id)
        
        return {
            "status": "success",
            "username": username,
            "assumable_roles": assumable_roles
        }
        
    except Exception as e:
        return {
            "status": "error",
            "username": username,
            "error": str(e),
            "assumable_roles": []
        }


def get_assumable_roles_for_user(client, username, account_id):
    """
    Obtiene los roles que un usuario puede asumir basándose en las políticas que tiene asignadas.
    
    Args:
        client: Cliente IAM de boto3
        username (str): Nombre del usuario
        account_id (str): ID de la cuenta AWS
    
    Returns:
        list: Lista de roles asumibles por el usuario
    """
    assumable_roles = []
    
    try:
        # Simular permisos para sts:AssumeRole en todos los roles de la cuenta
        all_roles_response = client.list_roles()
        all_roles = all_roles_response.get('Roles', [])
        
        # Crear lista de ARNs de roles para simular
        role_arns = [role['Arn'] for role in all_roles]
        
        if role_arns:
            user_arn = f"arn:aws:iam::{account_id}:user/{username}"
            
            # Simular permisos de AssumeRole para cada rol
            for role_arn in role_arns:
                try:
                    response = client.simulate_principal_policy(
                        PolicySourceArn=user_arn,
                        ActionNames=['sts:AssumeRole'],
                        ResourceArns=[role_arn]
                    )
                    
                    for result in response.get('EvaluationResults', []):
                        if result['EvalDecision'] == 'allowed':
                            # Extraer nombre del rol del ARN
                            role_name = role_arn.split('/')[-1]
                            assumable_roles.append({
                                'RoleName': role_name,
                                'RoleArn': role_arn,
                                'Source': 'Policy-based'
                            })
                except ClientError:
                    # Si falla la simulación para un rol específico, continuar
                    continue
                    
    except ClientError as e:
        print(f"Error getting assumable roles for user {username}: {e}")
    
    return assumable_roles


def collect_identity_center_data(session):
    """
    Collects data from AWS Identity Center (formerly AWS SSO).

    This function scans all regions to find an active Identity Center instance,
    then retrieves permission sets, groups, and account assignments to provide a
    comprehensive view of SSO configurations.

    Args:
        session (boto3.Session): The boto3 session for creating AWS clients.

    Returns:
        dict: A dictionary with the status, instance details, and a list of assignments,
              or an error message if not found or access is denied.

    Example:
        >>> sso_data = collect_identity_center_data(boto3.Session())
        >>> if sso_data['status'] == 'Found': print(sso_data['assignments'])
    """
    try:
        all_regions = get_all_aws_regions(session)
        instance_arn, identity_store_id, found_region = None, None, None

        for region in all_regions:
            try:
                regional_sso_client = session.client("sso-admin", region_name=region)
                instances = regional_sso_client.list_instances().get("Instances", [])
                if instances:
                    instance_arn = instances[0]['InstanceArn']
                    identity_store_id = instances[0]['IdentityStoreId']
                    found_region = region
                    break
            except ClientError:
                continue

        if not instance_arn:
            return {"status": "Not found", "message": "No active AWS Identity Center instances were found in any region."}

        sso_admin_client = session.client("sso-admin", region_name=found_region)
        identity_client = session.client("identitystore", region_name=found_region)

        group_map = {g['GroupId']: g['DisplayName'] for page in identity_client.get_paginator('list_groups').paginate(IdentityStoreId=identity_store_id) for g in page.get("Groups", [])}
        ps_map = {}
        for page in sso_admin_client.get_paginator('list_permission_sets').paginate(InstanceArn=instance_arn):
            for ps_arn in page.get("PermissionSets", []):
                details = sso_admin_client.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)
                ps_map[ps_arn] = details.get("PermissionSet", {}).get("Name", "Unknown")

        privileged_ps_names = ["AWSAdministratorAccess", "AdministratorAccess", "AWSPowerUserAccess", "PowerUserAccess"]
        assignments = []
        paginator_accounts = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')

        for ps_arn, ps_name in ps_map.items():
            for page in paginator_accounts.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for account_id in page.get("AccountIds", []):
                    paginator_assignments = sso_admin_client.get_paginator('list_account_assignments')
                    for assign_page in paginator_assignments.paginate(InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn):
                        for assignment in assign_page.get("AccountAssignments", []):
                            if assignment.get("PrincipalType") == "GROUP":
                                group_id = assignment.get("PrincipalId")
                                assignments.append({
                                    "AccountId": account_id, "PermissionSetArn": ps_arn,
                                    "PermissionSetName": ps_name, "GroupId": group_id,
                                    "GroupName": group_map.get(group_id, "Unknown Group"),
                                    "IsPrivileged": ps_name in privileged_ps_names
                                })

        return {
            "status": "Found", "instance_arn": instance_arn,
            "identity_store_id": identity_store_id,
            "assignments": sorted(assignments, key=lambda x: (x['GroupName'], x['PermissionSetName']))
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            return {"status": "Error", "message": "Access denied for 'sso-admin' or 'identitystore'."}
        return {"status": "Error", "message": f"Client error querying Identity Center: {str(e)}"}
    except Exception as e:
        return {"status": "General Error", "message": f"An unexpected error occurred: {str(e)}"}



def check_critical_permissions(session, users):
    """
    Uses iam:SimulatePrincipalPolicy to check if users have critical permissions.

    This function simulates a set of critical actions across Networking, CloudTrail,
    Databases, and WAF for each provided user and records which ones are allowed.

    Args:
        session (boto3.Session): The boto3 session for creating AWS clients.
        users (list): A list of user dictionaries to check.

    Returns:
        list: The list of users, with each user dictionary updated to include a
              'criticalPermissions' key detailing allowed actions.

    Example:
        >>> users_with_perms = check_critical_permissions(session, iam_users)
    """
    iam_client = session.client("iam")
    account_id = session.client("sts").get_caller_identity()["Account"]

    actions_map = {
        "network": ["ec2:CreateVpc", "ec2:DeleteVpc", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateNetworkAcl", "ec2:DeleteNetworkAcl"],
        "cloudtrail": ["cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail"],
        "database": ["rds:CreateDBInstance", "rds:DeleteDBInstance", "dynamodb:CreateTable", "dynamodb:DeleteTable"],
        "waf": ["wafv2:CreateWebACL", "wafv2:DeleteWebACL", "wafv2:UpdateWebACL"]
    }
    all_actions = [action for sublist in actions_map.values() for action in sublist]

    for user in users:
        user_arn = f"arn:aws:iam::{account_id}:user/{user['UserName']}"
        user["criticalPermissions"] = {category: [] for category in actions_map}

        try:
            response = iam_client.simulate_principal_policy(PolicySourceArn=user_arn, ActionNames=all_actions)
            for result in response.get("EvaluationResults", []):
                if result["EvalDecision"] == "allowed":
                    action_name = result["EvalActionName"]
                    for category, action_list in actions_map.items():
                        if action_name in action_list:
                            user["criticalPermissions"][category].append(action_name)
                            break
        except ClientError as e:
            print(f"Could not simulate the policy for {user['UserName']}: {e}")
            continue
    return users


def collect_federation_data(session):
    """
    Collects federation configuration, including IAM providers and Identity Center.

    This function consolidates information about how external identities can
    access the AWS account, covering both traditional SAML/OIDC and AWS SSO.

    Args:
        session (boto3.Session): The boto3 session for creating clients.

    Returns:
        dict: A dictionary containing 'iam_federation' and 'identity_center' data.

    Example:
        >>> federation_info = collect_federation_data(boto3.Session())
    """
    iam_client = session.client("iam")
    try:
        aliases = iam_client.list_account_aliases()['AccountAliases']
        account_alias = aliases[0] if aliases else None
    except ClientError:
        account_alias = None

    saml_providers = []
    try:
        response = iam_client.list_saml_providers()
        for provider in response.get('SAMLProviderList', []):
            saml_providers.append({"Arn": provider.get('Arn'), "CreateDate": provider.get('CreateDate').isoformat()})
    except ClientError:
        pass

    oidc_providers = []
    try:
        response = iam_client.list_open_id_connect_providers()
        for provider in response.get('OpenIDConnectProviderList', []):
            oidc_providers.append({"Arn": provider.get('Arn')})
    except ClientError:
        pass

    iam_federation_data = {"account_alias": account_alias, "saml_providers": saml_providers, "oidc_providers": oidc_providers}
    identity_center_data = collect_identity_center_data(session)

    return {"iam_federation": iam_federation_data, "identity_center": identity_center_data}


def collect_access_analyzer_data(session):
    """
    Collects findings from AWS Access Analyzer across all regions.

    It retrieves a summary of all active analyzers and lists all active findings
    that indicate external or public access to resources.

    Args:
        session (boto3.Session): The boto3 session for creating clients.

    Returns:
        dict: A dictionary containing a list of 'findings' and a 'summary' of analyzers.

    Example:
        >>> access_data = collect_access_analyzer_data(boto3.Session())
        >>> print(access_data['summary'])
    """
    all_regions = get_all_aws_regions(session)
    findings_results = []
    analyzers_summary = []

    for region in all_regions:
        try:
            analyzer_client = session.client("accessanalyzer", region_name=region)
            paginator_analyzers = analyzer_client.get_paginator('list_analyzers')
            account_analyzer_arn = None

            for page in paginator_analyzers.paginate():
                for analyzer in page.get('analyzers', []):
                    if analyzer.get('status') == 'ACTIVE':
                        analyzers_summary.append({"Region": region, "Name": analyzer.get('name'), "Type": analyzer.get('type'), "Arn": analyzer.get('arn')})
                    if analyzer.get('type') in ['ACCOUNT', 'ORGANIZATION'] and analyzer.get('status') == 'ACTIVE':
                        account_analyzer_arn = analyzer.get('arn')

            if not account_analyzer_arn:
                continue

            paginator_findings = analyzer_client.get_paginator('list_findings')
            for page in paginator_findings.paginate(analyzerArn=account_analyzer_arn, filter={'status': {'eq': ['ACTIVE']}}):
                for finding in page.get('findings', []):
                    principal = finding.get('principal', {})
                    if finding.get('isPublic') or 'AWS' in principal or 'Federated' in principal:
                        principal_display = "Public" if finding.get('isPublic') else principal.get('AWS') or principal.get('Federated')
                        findings_results.append({
                            "Region": region, "ResourceType": finding.get('resourceType'),
                            "Resource": finding.get('resource'), "Principal": principal_display,
                            "IsPublic": finding.get('isPublic', False),
                            "Action": ", ".join(finding.get('action', ['N/A'])),
                            "AnalyzedAt": finding.get('analyzedAt').isoformat()
                        })
        except (ClientError, Exception):
            continue

    findings_results.sort(key=lambda x: (x['Region'], x['ResourceType'], x['Resource']))
    return {"findings": findings_results, "summary": analyzers_summary}


def get_sso_group_members(session, group_id):
    """
    Gets the usernames of members in a specific AWS Identity Center group.

    Args:
        session (boto3.Session): The boto3 session for creating clients.
        group_id (str): The ID of the Identity Center group.

    Returns:
        list: A sorted list of usernames belonging to the group.

    Example:
        >>> members = get_sso_group_members(session, 'a1b2c3d4-...')
        >>> print(members)
    """
    all_regions = get_all_aws_regions(session)
    identity_store_id, found_region = None, None

    for region in all_regions:
        try:
            regional_sso_client = session.client("sso-admin", region_name=region)
            instances = regional_sso_client.list_instances().get("Instances", [])
            if instances:
                identity_store_id = instances[0]['IdentityStoreId']
                found_region = region
                break
        except ClientError:
            continue

    if not identity_store_id:
        raise Exception("Could not find an active AWS Identity Center instance.")

    identity_client = session.client("identitystore", region_name=found_region)
    user_members = []
    paginator = identity_client.get_paginator('list_group_memberships')

    for page in paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_id):
        for member in page.get('GroupMemberships', []):
            user_id = member.get('MemberId', {}).get('UserId')
            if user_id:
                try:
                    user_details = identity_client.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
                    user_members.append(user_details.get('UserName', 'User not found'))
                except ClientError:
                    user_members.append(f"User (ID: {user_id}) - Details Access Denied")
    return sorted(user_members)


def check_mfa_compliance_for_cli(session, users):
   """
   Analyzes IAM users to determine their MFA compliance specifically for CLI access.

   This function evaluates each user's MFA setup in the context of programmatic access,
   checking whether they have the necessary MFA devices and policies to ensure secure
   CLI usage. It identifies users who may be accessing AWS via CLI without proper
   MFA enforcement.

   Args:
       session (boto3.Session): The boto3 session for creating IAM clients.
       users (list): A list of IAM user dictionaries to analyze for MFA compliance.

   Returns:
       list: The input list of users, with each user dictionary updated to include
             an 'mfa_compliance' key containing compliance status and risk assessment.

   Example:
       >>> users_with_mfa_check = check_mfa_compliance_for_cli(session, user_list)
       >>> print(users_with_mfa_check[0]['mfa_compliance']['cli_compliant'])
   """
   iam_client = session.client("iam")
   account_id = session.client("sts").get_caller_identity()["Account"]

   # Define policy patterns that indicate MFA enforcement
   mfa_enforcement_patterns = [
       "aws:MultiFactorAuthPresent",
       "aws:MultiFactorAuthAge", 
       "MFA", "mfa"
   ]

   for user in users:
       username = user["UserName"]
       
       # Check if user has MFA devices configured
       has_mfa_device = len(user.get("MFADevices", [])) > 0
       
       # Check if user has active access keys (CLI capability)
       active_access_keys = [
           key for key in user.get("AccessKeys", []) 
           if key.get("Status") == "Active"
       ]
       has_active_access_keys = len(active_access_keys) > 0
       
       # Analyze attached policies for MFA requirements
       has_mfa_policy = False
       mfa_policy_sources = []
       
       try:
           # Check user's directly attached policies
           for policy_name in user.get("AttachedPolicies", []):
               try:
                   # Get policy details to check for MFA conditions
                   policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
                   if policy_name.startswith("arn:aws:iam::aws:"):
                       policy_arn = policy_name  # AWS managed policy
                   
                   policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                   policy_version = iam_client.get_policy_version(
                       PolicyArn=policy_arn,
                       VersionId=policy_response["Policy"]["DefaultVersionId"]
                   )
                   
                   policy_doc = str(policy_version["PolicyVersion"]["Document"])
                   if any(pattern in policy_doc for pattern in mfa_enforcement_patterns):
                       has_mfa_policy = True
                       mfa_policy_sources.append(f"User Policy: {policy_name}")
                       
               except (ClientError, KeyError):
                   continue
           
           # Check inline policies
           for inline_policy_name in user.get("InlinePolicies", []):
               try:
                   inline_policy = iam_client.get_user_policy(
                       UserName=username,
                       PolicyName=inline_policy_name
                   )
                   policy_doc = str(inline_policy["PolicyDocument"])
                   if any(pattern in policy_doc for pattern in mfa_enforcement_patterns):
                       has_mfa_policy = True
                       mfa_policy_sources.append(f"Inline Policy: {inline_policy_name}")
                       
               except ClientError:
                   continue
           
           # Check group policies
           for group_name in user.get("Groups", []):
               try:
                   # Check group's attached policies
                   group_policies = iam_client.list_attached_group_policies(GroupName=group_name)
                   for group_policy in group_policies["AttachedPolicies"]:
                       try:
                           policy_arn = group_policy["PolicyArn"]
                           policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                           policy_version = iam_client.get_policy_version(
                               PolicyArn=policy_arn,
                               VersionId=policy_response["Policy"]["DefaultVersionId"]
                           )
                           
                           policy_doc = str(policy_version["PolicyVersion"]["Document"])
                           if any(pattern in policy_doc for pattern in mfa_enforcement_patterns):
                               has_mfa_policy = True
                               mfa_policy_sources.append(f"Group '{group_name}': {group_policy['PolicyName']}")
                               
                       except (ClientError, KeyError):
                           continue
                   
                   # Check group's inline policies
                   group_inline_policies = iam_client.list_group_policies(GroupName=group_name)
                   for inline_policy_name in group_inline_policies["PolicyNames"]:
                       try:
                           inline_policy = iam_client.get_group_policy(
                               GroupName=group_name,
                               PolicyName=inline_policy_name
                           )
                           policy_doc = str(inline_policy["PolicyDocument"])
                           if any(pattern in policy_doc for pattern in mfa_enforcement_patterns):
                               has_mfa_policy = True
                               mfa_policy_sources.append(f"Group '{group_name}' Inline: {inline_policy_name}")
                               
                       except ClientError:
                           continue
                           
               except ClientError:
                   continue
       
       except Exception as e:
           print(f"Error analyzing MFA policies for user {username}: {e}")
       
       # Calculate risk level and compliance status
       risk_level = "low"
       cli_compliant = True
       
       if has_active_access_keys:
           if not has_mfa_device:
               risk_level = "critical"
               cli_compliant = False
           elif not has_mfa_policy:
               risk_level = "high" 
               cli_compliant = False
           else:
               risk_level = "low"
               cli_compliant = True
       else:
           # No access keys means no CLI access capability
           risk_level = "none"
           cli_compliant = True  # Compliant by virtue of no CLI access
       
       # Store compliance information in user object
       user["mfa_compliance"] = {
           "has_mfa_device": has_mfa_device,
           "has_active_access_keys": has_active_access_keys,
           "active_access_keys_count": len(active_access_keys),
           "has_mfa_policy": has_mfa_policy,
           "mfa_policy_sources": list(set(mfa_policy_sources)),  # Remove duplicates
           "cli_compliant": cli_compliant,
           "risk_level": risk_level,
           "analysis_notes": {
               "can_access_cli": has_active_access_keys,
               "mfa_configured": has_mfa_device,
               "mfa_enforced": has_mfa_policy,
               "compliance_summary": "Compliant" if cli_compliant else "Non-compliant"
           }
       }
   
   return users

def analyze_custom_policy(session, policy_name):
    """
    Analiza una política customer-managed específica y extrae información detallada.
    
    Args:
        session (boto3.Session): The boto3 session for creating clients.
        policy_name (str): Nombre de la política custom a analizar
        
    Returns:
        dict: Análisis completo de la política custom
    """
    iam_client = session.client("iam")
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    
    # Construir ARN de la política custom
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    
    try:
        # Obtener información de la política
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        policy = policy_response['Policy']
        
        # Obtener el documento de la versión actual
        policy_version_response = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy['DefaultVersionId']
        )
        
        policy_document = policy_version_response['PolicyVersion']['Document']
        
        # Analizar el contenido de la política
        analysis = analyze_policy_document(policy_document)
        
        # Obtener entidades que usan esta política
        entities_using_policy = get_entities_using_policy(iam_client, policy_arn)
        
        return {
            "status": "success",
            "policy_name": policy_name,
            "policy_arn": policy_arn,
            "metadata": {
                "policy_id": policy['PolicyId'],
                "creation_date": policy['CreateDate'].isoformat(),
                "update_date": policy['UpdateDate'].isoformat(),
                "default_version_id": policy['DefaultVersionId'],
                "attachment_count": policy['AttachmentCount'],
                "permissions_boundary_usage_count": policy.get('PermissionsBoundaryUsageCount', 0),
                "is_attachable": policy['IsAttachable']
            },
            "policy_document": policy_document,
            "analysis": analysis,
            "used_by": entities_using_policy
        }
        
    except iam_client.exceptions.NoSuchEntityException:
        return {
            "status": "error",
            "error": f"Custom policy '{policy_name}' not found. Make sure the policy name is correct and exists in this account."
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            return {
                "status": "error",
                "error": f"Access denied when trying to read policy '{policy_name}'. Check IAM permissions."
            }
        else:
            return {
                "status": "error",
                "error": f"Error analyzing policy '{policy_name}': {str(e)}"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Unexpected error analyzing policy '{policy_name}': {str(e)}"
        }


def analyze_policy_document(policy_document):
    """
    Analiza el documento JSON de una política y extrae información útil.
    
    Args:
        policy_document (dict): El documento de la política IAM
        
    Returns:
        dict: Análisis del contenido de la política
    """
    try:
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        analysis = {
            "statement_count": len(statements),
            "allows_statements": 0,
            "denies_statements": 0,
            "services_affected": set(),
            "actions_allowed": [],
            "actions_denied": [],
            "resources_wildcard": False,
            "principals_wildcard": False,
            "has_conditions": False,
            "privilege_level": "low",
            "security_concerns": []
        }
        
        admin_actions = {"*", "*:*"}
        high_risk_services = {"iam", "sts", "organizations", "account"}
        
        for statement in statements:
            effect = statement.get('Effect', 'Allow')
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            principals = statement.get('Principal', [])
            conditions = statement.get('Condition', {})
            
            # Normalizar a listas
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Contar tipos de statements
            if effect == 'Allow':
                analysis['allows_statements'] += 1
                analysis['actions_allowed'].extend(actions)
            else:
                analysis['denies_statements'] += 1
                analysis['actions_denied'].extend(actions)
            
            # Analizar servicios afectados
            for action in actions:
                if ':' in action:
                    service = action.split(':')[0]
                    analysis['services_affected'].add(service)
            
            # Detectar wildcards peligrosos
            if '*' in resources or any('*' in str(res) for res in resources):
                analysis['resources_wildcard'] = True
                
            if principals and ('*' in str(principals)):
                analysis['principals_wildcard'] = True
            
            # Detectar condiciones
            if conditions:
                analysis['has_conditions'] = True
            
            # Evaluar nivel de privilegio
            if any(action in admin_actions for action in actions):
                analysis['privilege_level'] = "critical"
                analysis['security_concerns'].append("Contains administrative (*) permissions")
            
            # Detectar acciones de alto riesgo
            for action in actions:
                service = action.split(':')[0] if ':' in action else action
                if service in high_risk_services:
                    if analysis['privilege_level'] not in ["critical"]:
                        analysis['privilege_level'] = "high"
                    analysis['security_concerns'].append(f"Contains {service.upper()} permissions")
        
        # Convertir sets a listas para JSON serialization
        analysis['services_affected'] = sorted(list(analysis['services_affected']))
        analysis['security_concerns'] = list(set(analysis['security_concerns']))  # Eliminar duplicados
        
        # Evaluar nivel de privilegio final
        if not analysis['security_concerns'] and analysis['resources_wildcard']:
            analysis['privilege_level'] = "medium"
        
        return analysis
        
    except Exception as e:
        return {
            "error": f"Error analyzing policy document: {str(e)}",
            "statement_count": 0,
            "privilege_level": "unknown"
        }


def get_entities_using_policy(iam_client, policy_arn):
    """
    Obtiene qué usuarios, grupos y roles están usando esta política.
    
    Args:
        iam_client: Cliente IAM de boto3
        policy_arn (str): ARN de la política
        
    Returns:
        dict: Entidades que usan la política
    """
    entities = {
        "users": [],
        "groups": [],
        "roles": []
    }
    
    try:
        # Obtener entidades que usan la política
        paginator = iam_client.get_paginator('list_entities_for_policy')
        
        for page in paginator.paginate(PolicyArn=policy_arn):
            # Usuarios
            for user in page.get('PolicyUsers', []):
                entities['users'].append({
                    'name': user['UserName'],
                    'id': user['UserId']
                })
            
            # Grupos
            for group in page.get('PolicyGroups', []):
                entities['groups'].append({
                    'name': group['GroupName'],
                    'id': group['GroupId']
                })
            
            # Roles
            for role in page.get('PolicyRoles', []):
                entities['roles'].append({
                    'name': role['RoleName'],
                    'id': role['RoleId']
                })
                
    except Exception as e:
        entities['error'] = f"Error getting entities using policy: {str(e)}"
    
    return entities

def check_root_mfa_status(session):
    """
    Verifica si el usuario root tiene MFA habilitado y si es hardware.
    
    Args:
        session (boto3.Session): The boto3 session for creating clients.
        
    Returns:
        dict: Estado del MFA del usuario root incluyendo tipo (hardware/virtual)
    """
    try:
        iam_client = session.client("iam")
        sts_client = session.client("sts")
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Obtener resumen de la cuenta para verificar MFA del root
        account_summary = iam_client.get_account_summary()['SummaryMap']
        
        # Verificar si el root tiene MFA habilitado
        root_mfa_enabled = account_summary.get('AccountMFAEnabled', 0) == 1
        
        # Obtener información adicional sobre dispositivos MFA virtuales
        virtual_mfa_devices = iam_client.list_virtual_mfa_devices()
        
        # LÓGICA CORREGIDA para detectar dispositivos MFA virtuales del root
        root_virtual_mfa_devices = []
        for device in virtual_mfa_devices['VirtualMFADevices']:
            user_info = device.get('User', {})
            serial_number = device.get('SerialNumber', '')
            
            # Verificar múltiples condiciones para identificar dispositivos del root
            is_root_device = (
                user_info.get('Arn') == f'arn:aws:iam::{account_id}:root' or
                user_info.get('UserId') == account_id or
                serial_number.endswith(':root') or
                'root' in serial_number.lower()
            )
            
            if is_root_device:
                root_virtual_mfa_devices.append(device)
        
        # NUEVA: Verificar tipo de MFA mediante Security Hub
        hardware_mfa_status = check_iam6_finding(session) if root_mfa_enabled else None
        
        result = {
            "root_mfa_enabled": root_mfa_enabled,
            "virtual_mfa_devices": len(root_virtual_mfa_devices),
            "account_summary_available": True
        }
        
        # Añadir información de hardware MFA si está disponible
        if hardware_mfa_status is not None:
            result.update({
                "mfa_is_hardware": hardware_mfa_status.get('is_hardware'),
                "iam6_finding_details": hardware_mfa_status.get('details', ''),
                "iam6_check_available": True
            })
        else:
            result.update({
                "mfa_is_hardware": None,
                "iam6_finding_details": 'Hardware MFA check skipped - root MFA not enabled',
                "iam6_check_available": False
            })
        
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            return {
                "root_mfa_enabled": None,
                "virtual_mfa_devices": 0,
                "mfa_is_hardware": None,
                "account_summary_available": False,
                "iam6_check_available": False,
                "error": "Access denied to check root MFA status. This requires iam:GetAccountSummary and iam:ListVirtualMFADevices permissions."
            }
        else:
            return {
                "root_mfa_enabled": None,
                "virtual_mfa_devices": 0,
                "mfa_is_hardware": None,
                "account_summary_available": False,
                "iam6_check_available": False,
                "error": f"Error checking root MFA: {str(e)}"
            }
    except Exception as e:
        return {
            "root_mfa_enabled": None,
            "virtual_mfa_devices": 0,
            "mfa_is_hardware": None,
            "account_summary_available": False,
            "iam6_check_available": False,
            "error": f"Unexpected error checking root MFA: {str(e)}"
        }

def check_iam6_finding(session):
    """
    Verifica específicamente el finding IAM.6 de Security Hub para determinar
    si el usuario root tiene hardware MFA configurado.
    
    Args:
        session (boto3.Session): The boto3 session for creating clients.
        
    Returns:
        dict: Estado del hardware MFA basado en Security Hub finding IAM.6
    """
    try:
        # Obtener todas las regiones disponibles
        all_regions = get_all_aws_regions(session)
        
        for region in all_regions:
            try:
                securityhub_client = session.client('securityhub', region_name=region)
                
                # Verificar que Security Hub esté habilitado en esta región
                try:
                    securityhub_client.describe_hub()
                except ClientError as e:
                    if e.response['Error']['Code'] in ['InvalidAccessException', 'SubscriptionRequiredException']:
                        continue  # Security Hub no está habilitado en esta región
                    raise
                
                # Buscar findings IAM.6 activos (que indican problema)
                response = securityhub_client.get_findings(
                    Filters={
                        'ComplianceStatus': [
                            {'Value': 'FAILED', 'Comparison': 'EQUALS'}
                        ],
                        'WorkflowStatus': [
                            {'Value': 'NEW', 'Comparison': 'EQUALS'},
                            {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
                        ],
                        'Title': [
                            {'Value': 'Hardware MFA should be enabled for the root user', 'Comparison': 'EQUALS'}
                        ]
                    },
                    MaxResults=10
                )
                
                findings = response.get('Findings', [])
                
                # También buscar por generador específico como fallback
                if not findings:
                    response_fallback = securityhub_client.get_findings(
                        Filters={
                            'GeneratorId': [
                                {'Value': 'aws-config', 'Comparison': 'EQUALS'}
                            ],
                            'ComplianceStatus': [
                                {'Value': 'FAILED', 'Comparison': 'EQUALS'}
                            ],
                            'WorkflowStatus': [
                                {'Value': 'NEW', 'Comparison': 'EQUALS'},
                                {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
                            ]
                        },
                        MaxResults=50  # Más resultados para filtrar
                    )
                    
                    # Filtrar manualmente por findings relacionados con root MFA
                    potential_findings = response_fallback.get('Findings', [])
                    findings = [
                        f for f in potential_findings 
                        if f.get('Title', '').lower().find('root') != -1 and 
                           f.get('Title', '').lower().find('mfa') != -1 and
                           (f.get('Title', '').lower().find('hardware') != -1 or
                            f.get('Description', '').lower().find('hardware') != -1)
                    ]
                
                if findings:
                    # Si hay findings activos de IAM.6, significa que NO tiene hardware MFA
                    finding = findings[0]  # Tomar el primer finding
                    return {
                        'is_hardware': False,
                        'details': f"Active Security Hub finding: {finding.get('Title', 'Root user should use hardware MFA')}",
                        'finding_region': region,
                        'compliance_status': finding.get('Compliance', {}).get('Status', 'FAILED')
                    }
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['InvalidAccessException', 'SubscriptionRequiredException']:
                    continue  # Security Hub no está disponible en esta región
                elif error_code == 'AccessDeniedException':
                    continue  # Sin permisos para Security Hub en esta región
                else:
                    print(f"Error checking Security Hub in {region}: {e}")
                    continue
            except Exception as e:
                print(f"Unexpected error checking Security Hub in {region}: {e}")
                continue
        
        # Si no encontramos findings activos en ninguna región, asumimos que tiene hardware MFA
        return {
            'is_hardware': True,
            'details': 'No active IAM.6 findings found - root user likely has hardware MFA enabled',
            'finding_region': None,
            'compliance_status': 'PASSED'
        }
        
    except Exception as e:
        return {
            'is_hardware': None,
            'details': f'Unable to check IAM.6 finding via Security Hub: {str(e)}',
            'finding_region': None,
            'compliance_status': 'UNKNOWN'
        }