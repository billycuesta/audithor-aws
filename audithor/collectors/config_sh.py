# collectors/config_sh.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def sh_check_regional_services(session, regions):
    """
    Checks the status of AWS Config and Security Hub in a list of regions.

    This function iterates through the provided regions to verify if AWS Config
    and AWS Security Hub are enabled. It lists any active Config Conformance

    Packs and enabled Security Hub standards. Crucially, it also generates and
    returns a map that links each individual Security Hub control ID to the
    security standard it belongs to.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.
        regions (list): A list of AWS region name strings to check.

    Returns:
        tuple: A tuple containing two elements:
               1. A list of dictionaries, where each dictionary summarizes the
                  service status for a single region.
               2. A dictionary that maps Security Hub control IDs (e.g., 'ACM.1')
                  to the ARN of their parent standard.

    Example:
        >>> import boto3
        >>>
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> regions_to_scan = ['us-east-1', 'eu-west-1']
        >>> statuses, control_map = sh_check_regional_services(aws_session, regions_to_scan)
        >>> print(f"Built a map for {len(control_map)} unique Security Hub controls.")
    """
    results = []
    # This map links a control ID (e.g., 'ACM.1') to its parent standard ARN
    control_to_standard_map = {}

    for region in regions:
        region_status = {
            "Region": region,
            "ConfigEnabled": False,
            "SecurityHubEnabled": False,
            "EnabledStandards": [],
            "EnabledConformancePacks": [],
            "ComplianceSummaries": []
        }
        
        # --- 1. Check AWS Config Status ---
        try:
            config_client = session.client("config", region_name=region)
            status = config_client.describe_configuration_recorder_status()
            recorders = status.get("ConfigurationRecordersStatus", [])
            if recorders and recorders[0].get("recording"):
                region_status["ConfigEnabled"] = True
                
                # Check for any enabled Conformance Packs
                try:
                    cp_response = config_client.describe_conformance_packs()
                    for cp in cp_response.get('ConformancePackDetails', []):
                        region_status["EnabledConformancePacks"].append(cp.get('ConformancePackName'))
                except ClientError:
                    pass # Ignore if call to describe conformance packs fails
        except ClientError:
            pass # Ignore if Config service is not available or accessible

        # --- 2. Check AWS Security Hub Status ---
        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub() # Throws an error if SH is not enabled
            region_status["SecurityHubEnabled"] = True
            
            # If enabled, get details about standards and controls
            try:
                standards_response = securityhub_client.get_enabled_standards()
                for standard in standards_response.get('StandardsSubscriptions', []):
                    standard_arn = standard.get('StandardsArn', 'unknown')
                    region_status["EnabledStandards"].append(standard_arn)
                    
                    sub_arn = standard.get('StandardsSubscriptionArn')
                    controls = securityhub_client.describe_standards_controls(
                        StandardsSubscriptionArn=sub_arn
                    ).get('Controls', [])

                    if not controls:
                        continue

                    # --- Build the Control-to-Standard Map ---
                    for control in controls:
                        control_id = control.get('ControlId')
                        if control_id:
                            control_to_standard_map[control_id] = standard_arn
                    
                    # Calculate compliance summary for this standard
                    # This data is kept in case it's useful for other reporting.
                    passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                    region_status["ComplianceSummaries"].append({
                        "standardArn": standard_arn,
                        "standardName": standard_arn.split('/standard/')[-1].replace('-', ' ').title(),
                        "totalControls": len(controls),
                        "passedCount": passed_count
                    })
            except ClientError:
                pass # Ignore if unable to get standards details
        except ClientError:
            pass # Ignore if Security Hub is not enabled in the region
            
        results.append(region_status)
    
    return results, control_to_standard_map

def collect_config_sh_status_only(session):
    """
    Provides a quick overview of the enablement status for Config and Security Hub.

    This is a lightweight wrapper function that calls the more comprehensive 
    'sh_check_regional_services' function but discards the detailed control map,
    returning only the high-level service status for each region. It is useful
    for when you only need to know if the services are on or off.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing a 'service_status' key, which holds a 
              list of dictionaries, each representing the status for one region.

    Example:
        >>> import boto3
        >>>
        >>> # This assumes the other required functions are available
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> overview = collect_config_sh_status_only(aws_session)
        >>> print(overview)
    """
    regions = get_all_aws_regions(session)
    
    # Call the comprehensive function and unpack the returned tuple.
    # The underscore '_' is used to intentionally discard the control map.
    service_status_list, _ = sh_check_regional_services(session, regions)
    
    return {
        "service_status": service_status_list
    }

def get_compliance_for_region(securityhub_client):
    """
    Calculates the compliance summary for enabled standards in a specific region.

    This function takes an initialized Security Hub client for an active region
    and calculates the compliance status for each enabled security standard, 
    including the percentage of passed controls.

    Args:
        securityhub_client (boto3.client): An initialized Boto3 Security Hub client
                                           for a specific AWS region.

    Returns:
        list: A list of dictionaries, where each dictionary is a compliance
              summary for one standard. Returns an empty list on error.

    Example:
        >>> import boto3
        >>>
        >>> sh_client = boto3.client("securityhub", region_name="us-east-1")
        >>> compliance_data = get_compliance_for_region(sh_client)
        >>> for standard in compliance_data:
        ...     print(f"{standard['standardName']}: {standard['compliancePercentage']}%")
    """
    compliance_summary = []
    try:
        enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])
        
        for standard in enabled_standards:
            standard_subscription_arn = standard.get('StandardsSubscriptionArn')
            standard_arn = standard.get('StandardsArn', 'N/A')
            standard_name = standard_arn.split('/standard/')[-1].replace('-', ' ').title()

            controls = securityhub_client.describe_standards_controls(
                StandardsSubscriptionArn=standard_subscription_arn
            ).get('Controls', [])

            if not controls:
                continue

            # Calculate compliance statistics
            passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
            total_controls = len(controls)
            
            # Avoid division by zero if there are no controls
            compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

            compliance_summary.append({
                "standardName": standard_name,
                "compliancePercentage": round(compliance_percentage, 2),
                "passedCount": passed_count,
                "totalControls": total_controls,
            })
            
    except Exception as e:
        print(f"    [!] Could not retrieve the compliance summary: {e}")

    return compliance_summary

def sh_get_security_hub_findings(session, service_status):
    """
    Retrieves all active Security Hub findings from enabled AWS regions.

    This function iterates only through the regions where Security Hub is known
    to be active, based on the provided service_status list. It uses a paginator
    to efficiently fetch all findings with a 'RecordState' of 'ACTIVE'.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.
        service_status (list): A list of dictionaries detailing the status of 
                               services per region, used to identify where
                               Security Hub is enabled.

    Returns:
        list: A consolidated list of all active Security Hub finding 
              dictionaries from across all enabled regions.

    Example:
        >>> import boto3
        >>>
        >>> # service_status is typically generated by another function
        >>> status = [{'Region': 'us-east-1', 'SecurityHubEnabled': True}]
        >>> aws_session = boto3.Session()
        >>> active_findings = sh_get_security_hub_findings(aws_session, status)
        >>> print(f"Found {len(active_findings)} active findings.")
    """
    all_findings = []
    
    # Create a list of regions where Security Hub is confirmed to be enabled
    active_regions = [r['Region'] for r in service_status if r['SecurityHubEnabled']]
    
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            
            # Filter for active findings only
            active_filter = {'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]}
            pages = paginator.paginate(Filters=active_filter)
            
            for page in pages:
                all_findings.extend(page.get('Findings', []))
                
        except ClientError:
            # If an API call fails (e.g., permissions), skip this region and continue.
            pass
            
    return all_findings

def collect_config_sh_data(session):
    """
    Aggregates all AWS Config and Security Hub data into a unified structure.

    This function serves as a primary data collector. It fetches regional service
    statuses, retrieves all active findings, and then processes the data. Its key
    responsibilities include:
    1. Reconstructing a compliance summary based on the actual findings to ensure
       data consistency across the application.
    2. Enriching each finding with the ARN of its parent standard.
    3. Sorting all findings by severity from CRITICAL to INFORMATIONAL.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A comprehensive dictionary containing the processed dataset with keys
              'service_status', 'findings', and 'compliance_summary'.

    Example:
        >>> import boto3
        >>>
        >>> # This assumes all required helper functions are available
        >>> aws_session = boto3.Session()
        >>> security_dashboard_data = collect_config_sh_data(aws_session)
        >>> print(f"Processed {len(security_dashboard_data['findings'])} findings.")
    """
    # --- 1. Initial Data Collection ---
    regions = get_all_aws_regions(session)
    service_status_results, control_map = sh_check_regional_services(session, regions)
    findings = sh_get_security_hub_findings(session, service_status_results)
    
    # --- 2. Reconstruct Compliance Summary from Findings for Consistency ---
    # First, build a template from the initial scan to get total control counts per standard.
    compliance_summary_map = {}
    for region_data in service_status_results:
        for summary in region_data.get("ComplianceSummaries", []):
            arn = summary['standardArn']
            if arn not in compliance_summary_map:
                compliance_summary_map[arn] = {
                    "standardArn": arn,
                    "standardName": summary['standardName'],
                    "totalControls": summary.get('totalControls', 0),
                    "passedCount": 0,
                    "failedCount": 0,
                    "warningCount": 0, 
                    "notAvailableCount": 0,
                    "otherCount": 0
                }

    # Now, iterate through actual findings to populate the counts.
    for finding in findings:
        compliance_info = finding.get('Compliance', {})
        status = compliance_info.get('Status')
        control_id = compliance_info.get('SecurityControlId')
        standard_arn = control_map.get(control_id)

        if standard_arn and standard_arn in compliance_summary_map:
            if status == 'PASSED':
                compliance_summary_map[standard_arn]['passedCount'] += 1
            elif status == 'FAILED':
                compliance_summary_map[standard_arn]['failedCount'] += 1
            elif status == 'WARNING':
                compliance_summary_map[standard_arn]['warningCount'] += 1
            elif status == 'NOT_AVAILABLE':
                compliance_summary_map[standard_arn]['notAvailableCount'] += 1

    # Finalize the summary list and calculate 'other' controls.
    final_summary = []
    for arn, data in compliance_summary_map.items():
        counted = (data['passedCount'] + data['failedCount'] + 
                   data['warningCount'] + data['notAvailableCount'])
        
        # 'otherCount' represents controls with no active findings (e.g., suppressed).
        # Ensure the result is never negative.
        data['otherCount'] = max(0, data['totalControls'] - counted)
        final_summary.append(data)

    # --- 3. Enrich Each Finding with its Parent Standard ARN ---
    # This ensures the frontend can always filter findings by standard.
    for finding in findings:
        control_id = finding.get('Compliance', {}).get('SecurityControlId')
        if control_id in control_map:
            standard_arn = control_map[control_id]
            # Ensure the ProductFields dictionary exists before adding the key.
            if 'ProductFields' not in finding:
                finding['ProductFields'] = {}
            # Add or overwrite the StandardsArn to ensure it's always present.
            finding['ProductFields']['StandardsArn'] = standard_arn

    # --- 4. Sort Findings by Severity ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(
        key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99)
    )

    return {
        "service_status": service_status_results,
        "findings": findings,
        "compliance_summary": final_summary
    }
