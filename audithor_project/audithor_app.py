# ==============================================================================
# audithor_app.py - FICHERO PRINCIPAL (REFACTORIZADO)
# ==============================================================================
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import threading
import webbrowser
from datetime import datetime, timedelta
import pytz
import json
import subprocess
import shutil
import boto3

# Importa el motor de reglas (sin cambios)
from rules import RULES_TO_CHECK, coverage_gaps
from collectors.network_policies import get_network_details_table
from collectors import secrets_manager
from botocore.exceptions import BotoCoreError, ClientError

# --- 1. IMPORTA TUS NUEVOS MÓDULOS ---
from collectors import (
    utils, iam, securityhub, exposure, guardduty, waf, cloudtrail,
    cloudwatch, inspector, kms, acm, compute, databases,
    network_policies, connectivity, config_sh, playground, ecr, codepipeline, inventory
)




def get_boto_session(access_key, secret_key, session_token=None):
    """Creates and returns a Boto3 session from credentials."""
    try:
        # If the session token is empty or None, don't include it
        if session_token:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )
        else:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        
        # Verify that the credentials are valid by making a simple call
        sts_client = session.client('sts')
        sts_client.get_caller_identity()
        
        return session
    except (BotoCoreError, ClientError) as e:
        # If credentials are invalid or another error occurs, return None
        print(f"[ERROR] Boto3 session could not be created: {e}")
        return None


# ==============================================================================
# CONF. APLICACIÓN FLASK
# ==============================================================================
app = Flask(__name__)
CORS(app)

# ==============================================================================
# ENDPOINTS API (ADAPTADOS)
# ==============================================================================

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/run-iam-audit', methods=['POST'])
def run_iam_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        iam_results = iam.collect_iam_data(session)
        iam_results["users"] = iam.check_critical_permissions(session, iam_results["users"])
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": iam_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting IAM data: {str(e)}"}), 500

@app.route('/api/run-securityhub-audit', methods=['POST'])
def run_securityhub_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        all_regions = utils.get_all_aws_regions(session)
        service_status = securityhub.check_security_hub_status_in_regions(session, all_regions)
        findings_data = securityhub.get_and_filter_security_hub_findings(session, service_status)
        enabled_service_status = [s for s in service_status if s['SecurityHubEnabled']]
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z") }, "results": { "servicesStatus": enabled_service_status, "findings": findings_data } })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Security Hub data: {str(e)}"}), 500

@app.route('/api/run-exposure-audit', methods=['POST'])
def run_exposure_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        exposure_results = exposure.collect_exposure_data(session)
        exposure_results["lambda_credentials"] = exposure.scan_lambda_credentials(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": exposure_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Internet exposure.: {str(e)}"}), 500

@app.route('/api/run-guardduty-audit', methods=['POST'])
def run_guardduty_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        guardduty_results = guardduty.collect_guardduty_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": guardduty_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting GuardDuty data: {str(e)}"}), 500

@app.route('/api/run-waf-audit', methods=['POST'])
def run_waf_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        waf_results = waf.collect_waf_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": waf_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting WAF data {str(e)}"}), 500

@app.route('/api/run-cloudtrail-lookup', methods=['POST'])
def run_cloudtrail_lookup():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    event_name = data.get('event_name')
    start_date_str = data.get('start_date')
    end_date_str = data.get('end_date')
    region = data.get('region')

    if not all([start_date_str, end_date_str, region]):
        return jsonify({"error": "Missing parameters. Required: 'start_date', 'end_date' and 'region'."}), 400
        
    try:
        start_time = datetime.strptime(start_date_str, '%d-%m-%Y').replace(tzinfo=pytz.utc)
        end_time = (datetime.strptime(end_date_str, '%d-%m-%Y') + timedelta(days=1, seconds=-1)).replace(tzinfo=pytz.utc)
    except ValueError:
        return jsonify({"error": "Invalid date format. Use: 'dd-mm-yyyy'."}), 400

    try:
        lookup_results = cloudtrail.lookup_cloudtrail_events(session, region, event_name, start_time, end_time)
        return jsonify({"results": lookup_results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-cloudwatch-audit', methods=['POST'])
def run_cloudwatch_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        cloudwatch_results = cloudwatch.collect_cloudwatch_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudwatch_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting CloudWatch/SNS data: {str(e)}"}), 500

@app.route('/api/run-inspector-audit', methods=['POST'])
def run_inspector_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inspector_status = inspector.collect_inspector_status(session)
        inspector_status["findings"] = [] # Default empty findings for fast scan
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_status })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Inspector status: {str(e)}"}), 500

@app.route('/api/run-acm-audit', methods=['POST'])
def run_acm_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        acm_results = acm.collect_acm_data_web(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": acm_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting ACM data: {str(e)}"}), 500

@app.route('/api/run-compute-audit', methods=['POST'])
def run_compute_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        compute_results = compute.collect_compute_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": compute_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Compute data: {str(e)}"}), 500

@app.route('/api/run-databases-audit', methods=['POST'])
def run_databases_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        database_results = databases.collect_database_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": database_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Databases data: {str(e)}"}), 500

@app.route('/api/run-network-policies-audit', methods=['POST'])
def run_network_policies_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        network_policies_results = network_policies.collect_network_policies_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": network_policies_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Network Policies data: {str(e)}"}), 500
        
@app.route('/api/run-config-sh-audit', methods=['POST'])
def run_config_sh_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        results = config_sh.collect_config_sh_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Config & Security Hub data: {str(e)}"}), 500

@app.route('/api/run-config-sh-status-audit', methods=['POST'])
def run_config_sh_status_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        results = config_sh.collect_config_sh_status_only(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Config & SH status: {str(e)}"}), 500


@app.route('/api/run-network-detail-audit', methods=['POST'])
def handle_network_detail_audit():
    """
    Handles the request to get detailed rules for a specific network resource.
    """
    # Obtenemos las credenciales y creamos la sesión de Boto3
    # (Asegúrate de que tu lógica para get_boto_session esté aquí)
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: No JSON payload found."}), 400

        access_key = data.get('access_key')
        secret_key = data.get('secret_key')
        session_token = data.get('session_token')

        session = get_boto_session(access_key, secret_key, session_token)
        if not session:
            return jsonify({"error": "Failed to create AWS session from provided credentials."}), 500

        # Extraemos el ID y la región del cuerpo de la petición
        resource_id = data.get('resource_id')
        region = data.get('region')

        if not resource_id or not region:
            return jsonify({"error": "Missing 'resource_id' or 'region' in the request payload."}), 400

        # --- LÓGICA CORREGIDA Y SIMPLIFICADA ---
        # Llamamos directamente a la función robusta que ya depuramos en network_policies.py
        details = get_network_details_table(session, resource_id, region)
        
        # Si la función devuelve un string que empieza con "Error:", lo tratamos como un error del lado del cliente
        if isinstance(details, str) and details.startswith("Error:"):
            return jsonify({"error": details}), 400

        # Si todo va bien, devolvemos el resultado
        return jsonify({"results": {"details_table": details}})

    except Exception as e:
        # Capturamos cualquier otro error inesperado y lo devolvemos de forma clara
        print(f"[ERROR] en handle_network_detail_audit: {e}") # Log para tu consola
        return jsonify({"error": f"An unexpected server error occurred: {str(e)}"}), 500

@app.route('/api/run-connectivity-audit', methods=['POST'])
def run_connectivity_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        connectivity_results = connectivity.collect_connectivity_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": connectivity_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting connectivity data: {str(e)}"}), 500

@app.route('/api/run-playground-audit', methods=['POST'])
def run_playground_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        data = request.get_json()
        source_arn = data.get('source_arn')
        target_arn = data.get('target_arn')
        if not source_arn or not target_arn:
            return jsonify({"error": "Source and destination ARN are required."}), 400

        path_results = playground.analyze_network_path_data(session, source_arn, target_arn)

        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": path_results })
    except ValueError as e: 
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error while analyzing the network route: {str(e)}"}), 500

@app.route('/api/run-kms-audit', methods=['POST'])
def run_kms_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        kms_results = kms.collect_kms_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": kms_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting KMS data: {str(e)}"}), 500

@app.route('/api/run-sslscan', methods=['POST'])
def run_sslscan():
    data = request.get_json()
    targets_str = data.get('target')
    if not targets_str:
        return jsonify({"error": "No target has been provided."}), 400
    
    results = playground.run_sslscan_on_targets(targets_str)
    return jsonify({"results": results})

@app.route('/run_executive_summary', methods=['POST'])
def run_executive_summary():
    audit_data = request.json
    if not audit_data:
        return jsonify({"error": "No audit data provided"}), 400

    executive_summary_findings = []
    for rule in RULES_TO_CHECK:
        check_function = rule.get("check_function")
        if callable(check_function):
            violating_resources_raw = check_function(audit_data)
            gaps = coverage_gaps(audit_data, rule.get("data_sources", []))
            if violating_resources_raw:
                affected_resources_structured = []
                for resource in violating_resources_raw:
                    if isinstance(resource, dict):
                        affected_resources_structured.append({
                            "display": f"{resource['resource']} in {resource['region']}",
                            "region": resource.get("region", "Global")
                        })
                    else:
                        affected_resources_structured.append({
                            "display": str(resource),
                            "region": "Global"
                        })
                
                finding = {
                    "rule_id": rule.get("rule_id"), "name": rule.get("name"),
                    "severity": rule.get("severity"), "description": rule.get("description"),
                    "remediation": rule.get("remediation"), "status": "🚩 RED FLAG",
                    "affected_resources": affected_resources_structured
                }
                if gaps:
                    finding["coverage"] = gaps
                executive_summary_findings.append(finding)
            elif gaps:
                executive_summary_findings.append({
                    "rule_id": rule.get("rule_id"), "name": rule.get("name"),
                    "severity": rule.get("severity"), "description": rule.get("description"),
                    "remediation": rule.get("remediation"), "status": "NOT ASSESSED",
                    "affected_resources": [], "coverage": gaps
                })
    return jsonify(executive_summary_findings)

@app.route('/api/run-federation-audit', methods=['POST'])
def run_federation_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        federation_results = iam.collect_federation_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": federation_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting federation data: {str(e)}"}), 500

@app.route('/api/run-access-analyzer-audit', methods=['POST'])
def run_access_analyzer_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        analyzer_results = iam.collect_access_analyzer_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": analyzer_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Access Analyzer data: {str(e)}"}), 500

@app.route('/api/run-inspector-findings-audit', methods=['POST'])
def run_inspector_findings_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inspector_findings = inspector.collect_inspector_findings(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_findings })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Inspector findings: {str(e)}"}), 500

@app.route('/api/get-sso-group-members', methods=['POST'])
def get_sso_group_members_endpoint():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    group_id = data.get('group_id')
    if not group_id:
        return jsonify({"error": "Group_id is required."}), 400

    try:
        members = iam.get_sso_group_members(session, group_id)
        return jsonify({"members": members})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-cloudtrail-audit', methods=['POST'])
def run_cloudtrail_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        # Esta función ahora devuelve trails, events y trailguard_findings
        cloudtrail_results = cloudtrail.collect_cloudtrail_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudtrail_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting CloudTrail data.: {str(e)}"}), 500

@app.route('/api/run-ecr-audit', methods=['POST'])
def run_ecr_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        ecr_results = ecr.collect_ecr_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": ecr_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting ECR data: {str(e)}"}), 500

@app.route('/api/run-simulate-policy', methods=['POST'])
def run_simulate_policy():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    try:
        data = request.get_json()
        username = data.get('username')
        actions = data.get('actions', [])
        include_mfa_context = data.get('include_mfa_context', False)
        
        if not username:
            return jsonify({"error": "Username is required."}), 400
        if not actions:
            return jsonify({"error": "At least one action is required."}), 400
        
        context_entries = []
        if include_mfa_context:
            context_entries = [
                {
                    'ContextKeyName': 'aws:MultiFactorAuthPresent',
                    'ContextKeyValues': ['false'],
                    'ContextKeyType': 'boolean'
                }
            ]
        
        simulation_results = playground.simulate_user_permissions(
            session, username, actions, context_entries
        )
        
        return jsonify({"results": simulation_results})
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Simulation error: {str(e)}"}), 500

@app.route('/api/run-simulate-lambda-policy', methods=['POST'])
def run_simulate_lambda_policy():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    try:
        data = request.get_json()
        function_name = data.get('function_name')
        region = data.get('region')
        actions = data.get('actions', [])
        
        if not function_name or not region:
            return jsonify({"error": "Function name and region are required."}), 400
        if not actions:
            return jsonify({"error": "At least one action is required."}), 400
        
        simulation_results = playground.simulate_lambda_permissions(
            session, function_name, region, actions
        )
        
        return jsonify({"results": simulation_results})
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Simulation error: {str(e)}"}), 500


@app.route('/api/run-codepipeline-audit', methods=['POST'])
def run_codepipeline_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        codepipeline_results = codepipeline.collect_codepipeline_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": codepipeline_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting CodePipeline data: {str(e)}"}), 500


@app.route('/api/run-inventory-audit', methods=['POST'])
def run_inventory_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inventory_results = inventory.collect_inventory_summary(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inventory_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting inventory data: {str(e)}"}), 500


@app.route('/api/get-user-assumable-roles', methods=['POST'])
def get_user_assumable_roles_endpoint():
    """
    Endpoint para obtener roles asumibles de un usuario específico bajo demanda.
    """
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username is required."}), 400
    
    try:
        result = iam.get_user_assumable_roles(session, username)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "username": username,
            "error": f"Unexpected error: {str(e)}",
            "assumable_roles": []
        }), 500

@app.route('/api/analyze-custom-policy', methods=['POST'])
def analyze_custom_policy_endpoint():
    """
    Endpoint para analizar una política custom específica.
    """
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    policy_name = data.get('policy_name')
    
    if not policy_name:
        return jsonify({"error": "Policy name is required."}), 400
    
    try:
        result = iam.analyze_custom_policy(session, policy_name)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"Unexpected error analyzing custom policy: {str(e)}"
        }), 500

@app.route('/api/run-s3-security-check', methods=['POST'])
def run_s3_security_check():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    bucket_name = data.get('bucket_name')
    
    if not bucket_name:
        return jsonify({"error": "Bucket name is required"}), 400
    
    try:
        s3_client = session.client('s3')
        
        security_analysis = {
            "bucket_name": bucket_name,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "configuration": {},
            "risk_score": 0
        }
        
        # 1. Check Public Access Block settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            pab_config = public_access_block['PublicAccessBlockConfiguration']
            security_analysis["configuration"]["public_access_block"] = pab_config
            
            if not pab_config.get('BlockPublicAcls', False):
                security_analysis["issues"].append("Public ACLs are not blocked")
                security_analysis["risk_score"] += 20
                
            if not pab_config.get('IgnorePublicAcls', False):
                security_analysis["issues"].append("Public ACLs are not ignored")
                security_analysis["risk_score"] += 20
                
            if not pab_config.get('BlockPublicPolicy', False):
                security_analysis["issues"].append("Public bucket policies are not blocked")
                security_analysis["risk_score"] += 25
                
            if not pab_config.get('RestrictPublicBuckets', False):
                security_analysis["issues"].append("Public bucket access is not restricted")
                security_analysis["risk_score"] += 15
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                security_analysis["issues"].append("CRITICAL: No Public Access Block configuration found")
                security_analysis["risk_score"] += 30
            else:
                security_analysis["warnings"].append(f"Could not check Public Access Block: {e.response['Error']['Code']}")
        
        # 2. Check bucket policy
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            import json
            policy = json.loads(bucket_policy['Policy'])
            security_analysis["configuration"]["has_bucket_policy"] = True
            
            # Analyze policy for public access
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if principal == "*" or (isinstance(principal, dict) and principal.get('AWS') == "*"):
                    security_analysis["issues"].append("Bucket policy allows public access via wildcard principal")
                    security_analysis["risk_score"] += 25
                    
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                security_analysis["configuration"]["has_bucket_policy"] = False
                security_analysis["warnings"].append("No bucket policy found - relying on ACLs only")
            else:
                security_analysis["warnings"].append(f"Could not check bucket policy: {e.response['Error']['Code']}")
        
        # 3. Check bucket encryption
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            security_analysis["configuration"]["encryption"] = encryption['ServerSideEncryptionConfiguration']
            security_analysis["recommendations"].append("Encryption is enabled - good security practice")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                security_analysis["issues"].append("No server-side encryption configured")
                security_analysis["risk_score"] += 10
                security_analysis["recommendations"].append("Enable server-side encryption (SSE-S3 or SSE-KMS)")
            else:
                security_analysis["warnings"].append(f"Could not check encryption: {e.response['Error']['Code']}")
        
        # 4. Check bucket versioning
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = versioning.get('Status', 'Disabled')
            security_analysis["configuration"]["versioning"] = versioning_status
            
            if versioning_status != 'Enabled':
                security_analysis["warnings"].append("Versioning is not enabled")
                security_analysis["recommendations"].append("Consider enabling versioning for data protection")
            
            mfa_delete = versioning.get('MfaDelete', 'Disabled')
            security_analysis["configuration"]["mfa_delete"] = mfa_delete
            if mfa_delete != 'Enabled':
                security_analysis["recommendations"].append("Consider enabling MFA Delete for critical buckets")
                
        except ClientError as e:
            security_analysis["warnings"].append(f"Could not check versioning: {e.response['Error']['Code']}")
        
        # 5. Check bucket logging
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' in logging:
                security_analysis["configuration"]["access_logging"] = True
                security_analysis["recommendations"].append("Access logging is enabled - good for audit trails")
            else:
                security_analysis["configuration"]["access_logging"] = False
                security_analysis["warnings"].append("Access logging is not enabled")
                security_analysis["recommendations"].append("Enable access logging for security monitoring")
                
        except ClientError as e:
            security_analysis["warnings"].append(f"Could not check logging: {e.response['Error']['Code']}")
        
        # 6. Check bucket ACL
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_read_grants = []
            public_write_grants = []
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI', '').endswith('AllUsers'):
                    permission = grant.get('Permission')
                    if permission in ['READ', 'FULL_CONTROL']:
                        public_read_grants.append(permission)
                        security_analysis["issues"].append(f"Public {permission} access via ACL")
                        security_analysis["risk_score"] += 20
                    if permission in ['WRITE', 'FULL_CONTROL']:
                        public_write_grants.append(permission)
                        security_analysis["issues"].append(f"CRITICAL: Public {permission} access via ACL")
                        security_analysis["risk_score"] += 30
            
            security_analysis["configuration"]["public_read_acl"] = len(public_read_grants) > 0
            security_analysis["configuration"]["public_write_acl"] = len(public_write_grants) > 0
            
        except ClientError as e:
            security_analysis["warnings"].append(f"Could not check ACL: {e.response['Error']['Code']}")
        
        # 7. Generate recommendations based on bucket name patterns
        bucket_lower = bucket_name.lower()
        if any(keyword in bucket_lower for keyword in ['log', 'backup', 'archive', 'dump']):
            security_analysis["recommendations"].insert(0, "URGENT: This appears to be a logs/backup bucket - public access should be removed immediately")
            security_analysis["risk_score"] += 15
            
        if any(keyword in bucket_lower for keyword in ['www', 'static', 'public', 'web']):
            security_analysis["recommendations"].append("This appears to be a web hosting bucket - ensure only necessary files are public")
            
        if any(keyword in bucket_lower for keyword in ['temp', 'test', 'dev']):
            security_analysis["recommendations"].append("This appears to be a temporary/development bucket - consider if public access is necessary")
        
        # 8. Final risk assessment - CORREGIDO PARA LIMITAR A 100
        security_analysis["risk_score"] = min(security_analysis["risk_score"], 100)
        
        if security_analysis["risk_score"] >= 80:
            risk_level = "CRITICAL"
        elif security_analysis["risk_score"] >= 60:
            risk_level = "HIGH"
        elif security_analysis["risk_score"] >= 40:
            risk_level = "MEDIUM"
        elif security_analysis["risk_score"] >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
            
        security_analysis["risk_level"] = risk_level
        
        # 9. Add general recommendations
        if not security_analysis["recommendations"]:
            security_analysis["recommendations"].append("Review bucket configuration regularly")
            
        security_analysis["recommendations"].extend([
            "Monitor CloudTrail logs for bucket access patterns",
            "Consider using CloudFront for public content delivery",
            "Implement least privilege access policies",
            "Regular security audits and access reviews"
        ])
        
        return jsonify({
            "status": "success",
            "analysis": security_analysis
        })
        
    except ClientError as e:
        return jsonify({
            "error": f"AWS error: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
        }), 400
    except Exception as e:
        return jsonify({
            "error": f"Unexpected error during security analysis: {str(e)}"
        }), 500
    
@app.route('/api/run-secrets-manager-audit', methods=['POST'])
def run_secrets_manager_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        secrets_results = secrets_manager.collect_secrets_manager_data(session)
        sts = session.client("sts")
        return jsonify({ 
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"], 
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            }, 
            "results": secrets_results 
        })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Secrets Manager data: {str(e)}"}), 500


# ==============================================================================
# EJECUCIÓN SERVIDOR
# ==============================================================================
if __name__ == '__main__':
    port = 5001
    url = f"http://127.0.0.1:{port}/"
    def open_browser():
        webbrowser.open_new(url)
    threading.Timer(1, open_browser).start()
    app.run(host='0.0.0.0', port=port, debug=False)
