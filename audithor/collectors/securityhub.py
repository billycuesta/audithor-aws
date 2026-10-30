import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions  # Relative import


def check_security_hub_status_in_regions(session, regions):
    """
    Checks Security Hub status in each region and retrieves compliance summaries.

    If Security Hub is active in a region, this function gets the compliance
    summary for each enabled standard (e.g., CIS, PCI DSS).

    Args:
        session (boto3.Session): The boto3 session for creating clients.
        regions (list): A list of AWS region names to check.

    Returns:
        list: A list of dictionaries, where each contains the region's status
              and compliance summaries for enabled standards.

    Example:
        >>> regions = ['us-east-1', 'eu-west-1']
        >>> status = check_security_hub_status_in_regions(boto3.Session(), regions)
        >>> print(status)
        [{'Region': 'us-east-1', 'SecurityHubEnabled': True, 'ComplianceSummaries': [...]}]
    """
    results = []
    for region in regions:
        region_status = {
            "Region": region,
            "SecurityHubEnabled": False,
            "ComplianceSummaries": []
        }

        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub()  # This call fails if SH is not enabled
            region_status["SecurityHubEnabled"] = True

            # Get enabled standards (CIS, PCI, etc.)
            enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])

            for standard in enabled_standards:
                standard_arn = standard.get('StandardsSubscriptionArn')
                standard_name_raw = standard.get('StandardsArn', 'N/A').split('/standard/')[-1].replace('-', ' ').title()

                # For each standard, get the status of all its controls
                controls = securityhub_client.describe_standards_controls(
                    StandardsSubscriptionArn=standard_arn
                ).get('Controls', [])

                if not controls:
                    continue

                # Calculate the compliance summary
                passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                total_controls = len(controls)
                compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

                # Store the summary for the standard
                region_status["ComplianceSummaries"].append({
                    "standardName": standard_name_raw,
                    "compliancePercentage": round(compliance_percentage, 2),
                    "passedCount": passed_count,
                    "totalControls": total_controls,
                })

        except ClientError:
            # This occurs if Security Hub is not active, which is an expected condition.
            pass

        results.append(region_status)

    return results

def get_and_filter_security_hub_findings(session, region_statuses):
    """
    Fetches and filters active Security Hub findings from enabled regions.
    """
    all_findings = []
    active_regions = [r['Region'] for r in region_statuses if r['SecurityHubEnabled']]
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            # Filtramos en la llamada a la API para ser más eficientes
            pages = paginator.paginate(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'RESOLVED', 'Comparison': 'NOT_EQUALS'}]
                }
            )
            for page in pages:
                all_findings.extend(page['Findings'])
        except ClientError:
            pass

    # Se mantienen todas tus categorizaciones
    iam_findings = [f for f in all_findings if 'IAM' in f.get('Compliance', {}).get('SecurityControlId', '')]
    exposure_keywords = ['public', 'internet-facing', 'exposed', 'open', '0.0.0.0/0', 's3', 'ec2', 'elb', 'rds', 'lambda', 'api gateway', 'cloudfront']
    exposure_findings = [f for f in all_findings if any(keyword in f.get('Title', '').lower() for keyword in exposure_keywords)]
    waf_findings = [f for f in all_findings if 'WAF' in f.get('Compliance', {}).get('SecurityControlId', '')]
    cloudtrail_findings = [f for f in all_findings if 'cloudtrail' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    cloudwatch_findings = [f for f in all_findings if 'cloudwatch' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    inspector_control_ids = ["Inspector.1", "Inspector.2", "Inspector.3", "Inspector.4", "Inspector.5", "Inspector.6"]
    inspector_findings = [f for f in all_findings if f.get('Compliance', {}).get('SecurityControlId') in inspector_control_ids]
    ecr_findings = [f for f in all_findings if
                    f.get('Compliance', {}).get('SecurityControlId', '').startswith('ECR.') or
                    'AwsEcrRepository' in f.get('Resources', [{}])[0].get('Type', '')]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    
    findings_lists = [iam_findings, exposure_findings, waf_findings, cloudtrail_findings, cloudwatch_findings, inspector_findings, ecr_findings]
    
    for findings_list in findings_lists:
        findings_list.sort(key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99))

    # --- LA SOLUCIÓN DEFINITIVA ---
    # Devolvemos tanto la lista completa que el frontend necesita, como las listas separadas.
    return {
        "findings": all_findings,  # <-- Esta es la clave que resuelve el problema.
        "iamFindings": iam_findings,
        "exposureFindings": exposure_findings,
        "wafFindings": waf_findings,
        "cloudtrailFindings": cloudtrail_findings,
        "cloudwatchFindings": cloudwatch_findings,
        "inspectorFindings": inspector_findings,
        "ecrFindings": ecr_findings
    }

def calculate_compliance_from_findings(all_findings):
    """
    Calculates compliance status for each standard based on a list of findings.

    This function processes raw findings to determine PASSED/FAILED counts for
    each security standard they belong to.

    Args:
        all_findings (list): A list of raw Security Hub finding dictionaries.

    Returns:
        list: A summary list with compliance percentages and counts for each standard.

    Example:
        >>> # Assuming 'raw_findings' is a list of findings from Security Hub
        >>> compliance_summary = calculate_compliance_from_findings(raw_findings)
        >>> print(compliance_summary)
        [{'standardName': 'Aws Foundational Security Best Practices V1.0.0', ...}]
    """
    compliance_data = {}

    for finding in all_findings:
        # We are only interested in findings that are part of a security standard.
        if 'Compliance' not in finding or not finding['Compliance'].get('SecurityControlId'):
            continue

        standard_arn = finding.get('ProductFields', {}).get('StandardsArn', 'N/A')
        control_status = finding.get('Compliance', {}).get('Status', 'UNKNOWN')

        if standard_arn not in compliance_data:
            compliance_data[standard_arn] = {'passed': 0, 'failed': 0, 'other': 0}

        if control_status == 'PASSED':
            compliance_data[standard_arn]['passed'] += 1
        elif control_status == 'FAILED':
            compliance_data[standard_arn]['failed'] += 1
        else:
            compliance_data[standard_arn]['other'] += 1

    # Process the counts to return a summary with percentages.
    summary_list = []
    for arn, counts in compliance_data.items():
        total_controls_found = counts['passed'] + counts['failed']
        if total_controls_found > 0:
            percentage = round((counts['passed'] / total_controls_found) * 100, 2)
            standard_name = arn.split('/standard/')[-1].replace('-', ' ').title() if '/standard/' in arn else arn

            summary_list.append({
                "standardArn": arn,
                "standardName": standard_name,
                "compliancePercentage": percentage,
                "passedCount": counts['passed'],
                "failedCount": counts['failed'],
                "otherCount": counts['other'],
                "totalControls": total_controls_found
            })

    return summary_list