# collectors/utils.py
import boto3
from botocore.exceptions import ClientError
from .diagnostics import AWS_CONFIG, classify_error

def get_session(data, raise_errors=False):
    try:
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
    except Exception as e:
        if raise_errors:
            raise
        category = classify_error(e)["category"]
        return None, f"AWS credentials could not be validated ({category})"
    
def get_all_aws_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [region['RegionName'] for region in ec2.describe_regions()['Regions']]