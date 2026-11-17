# collectors/utils.py
import os
import ipaddress
import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound
from .diagnostics import AWS_CONFIG, classify_error

PROFILE_FORBIDDEN = "Profile scans are only available when Audithor is bound to localhost."

def profiles_enabled():
    host = os.environ.get("AUDITHOR_HOST", "127.0.0.1")
    if host in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

def list_aws_profiles():
    enabled = profiles_enabled()
    if not enabled:
        return {"profiles": [], "default": None, "enabled": False}
    try:
        profiles = sorted(boto3.Session().available_profiles)
        preferred = os.environ.get("AWS_PROFILE")
        default = preferred if preferred in profiles else "default" if "default" in profiles else None
        return {"profiles": profiles, "default": default, "enabled": True}
    except (BotoCoreError, ProfileNotFound, ValueError):
        return {"profiles": [], "default": None, "enabled": True, "error": "AWS profiles could not be read."}

def sso_login_message(profile):
    return f"AWS SSO session expired or missing: run `aws sso login --profile {profile}`"

def get_session(data, raise_errors=False):
    profile = data.get("profile")
    profile_mode = isinstance(profile, str) and bool(profile)
    try:
        if profile_mode:
            if not profiles_enabled():
                return None, PROFILE_FORBIDDEN
            available = boto3.Session().available_profiles
            if profile not in available:
                return None, f"Unknown AWS profile: {profile}"
            session = boto3.Session(profile_name=profile)
        else:
            access_key = data.get('access_key')
            secret_key = data.get('secret_key')
            session_token = data.get('session_token')
            if not access_key or not secret_key:
                return None, "Access Key or Secret Key not provided."
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )
        sts = session.client("sts", config=AWS_CONFIG)
        session._audithor_account_id = sts.get_caller_identity()["Account"]
        return session, None
    except (BotoCoreError, ClientError, ProfileNotFound) as e:
        if raise_errors:
            raise
        category = classify_error(e)["category"]
        if profile_mode and category == "sso_login_required":
            return None, sso_login_message(profile)
        return None, f"AWS credentials could not be validated ({category})"
    except Exception:
        if raise_errors:
            raise
        return None, "AWS credentials could not be validated (aws_error)"
    
def get_all_aws_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [region['RegionName'] for region in ec2.describe_regions()['Regions']]