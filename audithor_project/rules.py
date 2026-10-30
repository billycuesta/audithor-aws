# ==============================================================================
# rules.py - Motor de Reglas para AudiThor-AWS (ACTUALIZADO)
# ==============================================================================
from datetime import datetime, timezone, timedelta

# ------------------------------------------------------------------------------
# 1. Definición de Niveles de Severidad
# ------------------------------------------------------------------------------
SEVERITY = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Medio",
    "LOW": "Bajo",
    "INFO": "Informativo"
}

# ------------------------------------------------------------------------------
# 2. Funciones de Chequeo de Reglas
# ------------------------------------------------------------------------------

def check_mfa_for_all_users(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        if not user.get("MFADevices"):
            failing_resources.append(user.get("arn", user.get("UserName")))
    return failing_resources

def check_iam_access_key_age(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    ninety_days = 90
    now = datetime.now(timezone.utc)
    for user in users:
        for key in user.get("AccessKeys", []):
            try:
                create_date_str = key.get("CreateDate")
                create_date = datetime.fromisoformat(create_date_str)
                age = now - create_date
                if age.days > ninety_days:
                    user_identifier = user.get("arn", user.get("UserName"))
                    if user_identifier not in failing_resources:
                        failing_resources.append(user_identifier)
            except (ValueError, TypeError):
                continue
    return failing_resources

def check_password_policy_strength(audit_data):
    """
    Verifica la fortaleza de la política de contraseñas y devuelve detalles específicos
    de los requisitos que no se cumplen.
    """
    policy = audit_data.get("iam", {}).get("password_policy", {})
    
    if policy.get("Error"):
        return [{"resource": "Account Password Policy - Not configured", "region": "Global"}]
    
    # Lista de verificaciones con sus detalles específicos
    failed_checks = []
    
    # Verificación de longitud mínima
    min_length = policy.get("MinimumPasswordLength", 0)
    if min_length < 12:
        failed_checks.append(f"Minimum length: {min_length} (required: ≥12)")
    
    # Verificación de mayúsculas
    if not policy.get("RequireUppercaseCharacters"):
        failed_checks.append("Missing requirement: Uppercase letters")
    
    # Verificación de minúsculas
    if not policy.get("RequireLowercaseCharacters"):
        failed_checks.append("Missing requirement: Lowercase letters")
    
    # Verificación de números
    if not policy.get("RequireNumbers"):
        failed_checks.append("Missing requirement: Numbers")
    
    # Verificación de símbolos
    if not policy.get("RequireSymbols"):
        failed_checks.append("Missing requirement: Symbols")
    
    # Verificación de expiración
    max_age = policy.get("MaxPasswordAge")
    if not max_age or max_age > 90:
        if max_age:
            failed_checks.append(f"Password expiration: {max_age} days (required: ≤90)")
        else:
            failed_checks.append("Password expiration: Not set (required: ≤90 days)")
    
    # Verificación de reutilización
    reuse_prevention = policy.get("PasswordReusePrevention", 0)
    if reuse_prevention < 4:
        failed_checks.append(f"Password reuse prevention: {reuse_prevention} (required: ≥4)")
    
    # Si hay verificaciones fallidas, devolver los detalles específicos
    if failed_checks:
        # Crear un mensaje detallado con todos los problemas
        detailed_message = "Account Password Policy - Issues: " + "; ".join(failed_checks)
        return [{"resource": detailed_message, "region": "Global"}]
    
    return []



def check_guardduty_disabled(audit_data):
    """Verifica si GuardDuty está deshabilitado o suspendido."""
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])

    if not guardduty_status:
        failing_resources.append({"resource": "GuardDuty (Todas las regiones)", "region": "Global"})
        return failing_resources

    for status in guardduty_status:
        if status.get("Status") != "Enabled":
            failing_resources.append({
                "resource": "GuardDuty",
                "region": status.get('Region')
            })
    return failing_resources

def check_config_disabled(audit_data):
    """Verifica si AWS Config está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    if not any(s.get("ConfigEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "AWS Config (Todas las regiones)", "region": "Global"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("ConfigEnabled"):
            failing_resources.append({
                "resource": "AWS Config",
                "region": status.get('Region')
            })
    return failing_resources

def check_security_hub_disabled(audit_data):
    """Verifica si AWS Security Hub está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    if not any(s.get("SecurityHubEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "Security Hub (Todas las regiones)", "region": "Global"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("SecurityHubEnabled"):
            failing_resources.append({
                "resource": "Security Hub",
                "region": status.get('Region')
            })
    return failing_resources

def check_pci_dss_3_2_1_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'PCI DSS v3.2.1' está habilitado.
    """
    failing_resources = []
    service_status = audit_data.get("config_sh", {}).get("service_status", [])
    
    regions_with_standard = set()
    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "pci-dss" in arn_lower and "3.2.1" in arn_lower:
                regions_with_standard.add(region_status.get("Region"))
    
    all_regions = [s.get("Region") for s in service_status]

    for region in all_regions:
        if region not in regions_with_standard:
            failing_resources.append({"resource": "PCI DSS v3.2.1 Standard", "region": region})
    
    if not service_status:
        return [{"resource": "PCI DSS v3.2.1 Standard", "region": "Global"}]
        
    return failing_resources

def check_pci_dss_4_0_1_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'PCI DSS v4.0.1' está habilitado.
    """
    failing_resources = []
    service_status = audit_data.get("config_sh", {}).get("service_status", [])
    
    regions_with_standard = set()
    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "pci-dss" in arn_lower and "4.0.1" in arn_lower:
                regions_with_standard.add(region_status.get("Region"))
    
    all_regions = [s.get("Region") for s in service_status]

    for region in all_regions:
        if region not in regions_with_standard:
            failing_resources.append({"resource": "PCI DSS v4.0.1 Standard", "region": region})
    
    if not service_status:
        return [{"resource": "PCI DSS v4.0.1 Standard", "region": "Global"}]
        
    return failing_resources

def check_cis_1_2_0_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'CIS AWS Foundations Benchmark v1.2.0' está habilitado.
    """
    failing_resources = []
    service_status = audit_data.get("config_sh", {}).get("service_status", [])
    
    regions_with_standard = set()
    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            # Modificación de la lógica para ser más flexible con la versión.
            # Se aceptarán tanto la v1.2.0 como la v3.0.0.
            if "cis-aws-foundations-benchmark" in arn_lower:
                regions_with_standard.add(region_status.get("Region"))
    
    all_regions = [s.get("Region") for s in service_status]

    for region in all_regions:
        if region not in regions_with_standard:
            failing_resources.append({"resource": "CIS AWS Foundations Benchmark v1.2.0 Standard", "region": region})
    
    if not service_status:
        return [{"resource": "CIS AWS Foundations Benchmark v1.2.0 Standard", "region": "Global"}]
        
    return failing_resources


def check_aws_foundational_security_standard_enabled(audit_data):
    """
    Verifica si el estándar 'AWS Foundational Security Best Practices v1.0.0' está habilitado.
    """
    failing_resources = []
    service_status = audit_data.get("config_sh", {}).get("service_status", [])
    
    regions_with_standard = set()
    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "aws-foundational-security-best-practices" in arn_lower:
                regions_with_standard.add(region_status.get("Region"))
    
    all_regions = [s.get("Region") for s in service_status]

    for region in all_regions:
        if region not in regions_with_standard:
            failing_resources.append({"resource": "AWS Foundational Security Best Practices Standard", "region": region})

    if not service_status:
        return [{"resource": "AWS Foundational Security Best Practices Standard", "region": "Global"}]
        
    return failing_resources


def check_inspector_platform_eol(audit_data):
    """
    Busca hallazgos de Inspector que indiquen que una plataforma ha llegado al final de su vida útil (End of Life).
    """
    failing_resources = []
    inspector_findings = audit_data.get("inspector", {}).get("findings", [])

    for finding in inspector_findings:
        # Comparamos si la cadena de texto está presente en el título
        if "Platform End Of Life" in finding.get("title", ""):
            if finding.get("resources"):
                resource_id = finding["resources"][0].get("id", "ID no encontrado")
                failing_resources.append(resource_id)
                
    return failing_resources

def check_inspector_old_critical_findings(audit_data):
    """
    Busca hallazgos de Inspector con severidad Crítica o Alta que tengan una antigüedad mayor a 30 días.
    """
    failing_resources = []
    inspector_findings = audit_data.get("inspector", {}).get("findings", [])
    
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    for finding in inspector_findings:
        severity = finding.get("severity")
        
        if severity in ["CRITICAL", "HIGH"]:
            try:
                first_observed_str = finding.get("firstObservedAt")
                if first_observed_str:
                    
                    # --- LÍNEA CORREGIDA ---
                    # Usamos strptime con el formato correcto en lugar de fromisoformat
                    finding_date = datetime.strptime(first_observed_str, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                    
                    if finding_date < thirty_days_ago:
                        title = finding.get("title", "Título no disponible")
                        resource_id = "Recurso no disponible"
                        if finding.get("resources"):
                            resource_id = finding["resources"][0].get("id", "ID no disponible")
                        
                        failing_resources.append(f"{title} (Recurso: {resource_id})")

            except (ValueError, TypeError) as e:
                print(f"[WARN] No se pudo procesar la fecha para un finding de Inspector: {e}")
                continue
                
    return failing_resources

def check_user_has_attached_policies(audit_data):
    """Verifica si un usuario tiene políticas de IAM adjuntadas directamente."""
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        if user.get("AttachedPolicies"):
            failing_resources.append(user.get("UserName"))
    return failing_resources

def check_guardduty_malware_protection_disabled_with_ec2(audit_data):
    """
    Verifica si GuardDuty Malware Protection para EC2 está desactivado en regiones
    donde existen instancias EC2 y GuardDuty está habilitado.
    """
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    
    for status in guardduty_status:
        region = status.get("Region")
        
        cond1_gd_enabled = status.get("Status") == "Enabled"
        cond2_malware_disabled = status.get("EC2 Malware Protection") in ["Deshabilitado", "N/A"]
        cond3_ec2_present = region in regions_with_ec2

        if (cond1_gd_enabled and cond2_malware_disabled and cond3_ec2_present):
            failing_resources.append({
                "resource": "GuardDuty Malware Protection para EC2",
                "region": region
            })
    return failing_resources

def check_no_cloudtrail_in_region(audit_data):
    """
    Verifica cada región para asegurar que al menos un trail de CloudTrail está definido,
    teniendo en cuenta los trails multi-región.
    """
    all_regions = audit_data.get("networkPolicies", {}).get("all_regions", [])
    if not all_regions:
        return [] 

    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    # Si no se recibe ningún trail, todas las regiones fallan.
    if not trails:
        return [{"resource": "CloudTrail", "region": region} for region in all_regions]

    # Comprobar si existe algún trail multi-región.
    is_any_trail_multiregion = any(trail.get("IsMultiRegionTrail") for trail in trails)
    if is_any_trail_multiregion:
        # Si existe, todas las regiones están cubiertas.
        return [] 
    
    # Si no hay trail multi-región, verificamos región por región.
    failing_resources = []
    regions_with_trails = {trail.get("HomeRegion") for trail in trails}
    for region in all_regions:
        if region not in regions_with_trails:
            failing_resources.append({
                "resource": "CloudTrail",
                "region": region
            })
    return failing_resources

def check_inspector_ec2_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de EC2 de Inspector está desactivado en regiones donde existen instancias EC2.
    """
    failing_resources = []
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])

    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    inspector_ec2_scan_status = {status['Region']: status.get('ScanEC2') for status in inspector_status}

    for region in regions_with_ec2:
        scan_status = inspector_ec2_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector EC2 Scanning",
                "region": region
            })
    return failing_resources

def check_inspector_lambda_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de Lambda de Inspector está desactivado en regiones donde existen funciones Lambda.
    """
    failing_resources = []
    lambda_functions = audit_data.get("compute", {}).get("lambda_functions", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])

    regions_with_lambdas = {function['Region'] for function in lambda_functions}
    inspector_lambda_scan_status = {status['Region']: status.get('ScanLambda') for status in inspector_status}

    for region in regions_with_lambdas:
        scan_status = inspector_lambda_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector Lambda Scanning",
                "region": region
            })
    return failing_resources

def check_inspector_ecr_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de ECR de Inspector está desactivado en regiones donde existen repositorios.
    """
    failing_resources = []
    ecr_repositories = audit_data.get("ecr", {}).get("repositories", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
    
    regions_with_ecr = {repo['Region'] for repo in ecr_repositories}
    inspector_ecr_scan_status = {status['Region']: status.get('ScanECR') for status in inspector_status}
    
    for region in regions_with_ecr:
        scan_status = inspector_ecr_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector ECR Scanning",
                "region": region
            })
            
    return failing_resources

# rules.py

def check_network_connectivity_exists(audit_data):
    """
    Verifica si existen componentes de red avanzados y devuelve una lista
    de los tipos de servicio específicos encontrados.
    """
    # Lista para almacenar los nombres de los servicios detectados
    found_services = []
    
    # Obtener los datos de conectividad de forma segura
    connectivity_data = audit_data.get("connectivity", {})
    
    # Comprobar cada tipo de servicio y añadir su nombre a la lista si existe
    if connectivity_data.get("peering_connections"):
        found_services.append({"resource": "VPC Peering Connections", "region": "Global"})
        
    if connectivity_data.get("tgw_attachments"):
        found_services.append({"resource": "Transit Gateway Attachments", "region": "Global"})
        
    if connectivity_data.get("vpn_connections"):
        found_services.append({"resource": "Site-to-Site VPN Connections", "region": "Global"})
        
    if connectivity_data.get("vpc_endpoints"):
        found_services.append({"resource": "VPC Endpoints", "region": "Global"})

    # Devolver la lista de servicios encontrados
    return found_services


def check_acm_expired_certificates(audit_data):
    """
    Verifica si existen certificados de ACM que han expirado.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de certificados
    certificates = audit_data.get("acm", {}).get("certificates", [])

    for cert in certificates:
        if cert.get("Status") == "EXPIRED":
            # Añadimos el dominio del certificado expirado a la lista de recursos fallidos
            failing_resources.append(cert.get("DomainName", cert.get("CertificateArn")))
            
    return failing_resources

def check_cloudtrail_kms_encryption_disabled(audit_data):
    """
    Verifica si los trails de CloudTrail tienen el cifrado con KMS habilitado.
    """
    failing_resources = []
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        if not trail.get("KmsKeyId"):
            failing_resources.append({
                "resource": trail.get("Name", trail.get("TrailARN")),
                "region": trail.get("HomeRegion", "Unknown Region")
            })
            
    return failing_resources

def check_cloudtrail_log_file_validation_disabled(audit_data):
    """
    Verifica si los trails de CloudTrail tienen la validación de integridad de logs activada.
    """
    failing_resources = []
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        if not trail.get("LogFileValidationEnabled"):
            failing_resources.append({
                "resource": trail.get("Name", trail.get("TrailARN")),
                "region": trail.get("HomeRegion", "Unknown Region")
            })
            
    return failing_resources

def check_rds_publicly_accessible(audit_data):
    """
    Verifica si existen instancias de RDS configuradas con acceso público.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de instancias RDS
    rds_instances = audit_data.get("databases", {}).get("rds_instances", [])

    for instance in rds_instances:
        # La clave 'PubliclyAccessible' será True si la opción está activada
        if instance.get("PubliclyAccessible"):
            failing_resources.append({
                "resource": instance.get("DBInstanceIdentifier", "ID Desconocido"),
                "region": instance.get("Region", "Región Desconocida")
            })
            
    return failing_resources

def check_alb_outdated_tls_policy(audit_data):
    """
    Revisa los balanceadores de carga públicos (ALB/NLB) en busca de listeners
    que soporten versiones de TLS obsoletas (inferiores a TLSv1.2).
    """
    failing_resources = []
    # Navegamos de forma segura hasta los datos de balanceadores de carga por región
    lb_data_by_region = audit_data.get("exposure", {}).get("details", {}).get("ALB/NLB Public", {})

    # Iteramos sobre cada región que tiene balanceadores públicos
    for region, load_balancers in lb_data_by_region.items():
        for lb in load_balancers:
            # Iteramos sobre cada listener del balanceador
            for listener in lb.get("listeners", []):
                tls_versions = listener.get("tlsVersions", [])
                # Comprobamos si alguna de las versiones es obsoleta
                if any(version in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for version in tls_versions):
                    failing_resources.append({
                        "resource": f"{lb.get('name')} (Listener en puerto: {listener.get('port')})",
                        "region": region
                    })
            
    return failing_resources

def check_rds_instance_unencrypted(audit_data):
    """
    Verifica si existen instancias RDS standalone sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    rds_instances = audit_data.get("databases", {}).get("rds_instances", [])
    for instance in rds_instances:
        if not instance.get("Encrypted"):
            failing_resources.append({
                "resource": instance.get("DBInstanceIdentifier"),
                "region": instance.get("Region")
            })
    return failing_resources

def check_aurora_cluster_unencrypted(audit_data):
    """
    Verifica si existen clústeres Aurora sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    aurora_clusters = audit_data.get("databases", {}).get("aurora_clusters", [])
    for cluster in aurora_clusters:
        if not cluster.get("Encrypted"):
            failing_resources.append({
                "resource": cluster.get("ClusterIdentifier"),
                "region": cluster.get("Region")
            })
    return failing_resources

def check_dynamodb_table_unencrypted(audit_data):
    """
    Verifica si existen tablas de DynamoDB sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    dynamodb_tables = audit_data.get("databases", {}).get("dynamodb_tables", [])
    for table in dynamodb_tables:
        if table.get("Encrypted") is False:
            failing_resources.append({
                "resource": table.get("TableName"),
                "region": table.get("Region")
            })
    return failing_resources

def check_docdb_cluster_unencrypted(audit_data):
    """
    Verifica si existen clústeres de DocumentDB sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    docdb_clusters = audit_data.get("databases", {}).get("documentdb_clusters", [])
    for cluster in docdb_clusters:
        if not cluster.get("Encrypted"):
            failing_resources.append({
                "resource": cluster.get("ClusterIdentifier"),
                "region": cluster.get("Region")
            })
    return failing_resources

def check_ec2_publicly_exposed(audit_data):
    """
    Checks for EC2 instances that have a public IP address assigned.
    """
    failing_resources = []
    # Safely navigate to the list of EC2 instances
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    for instance in ec2_instances:
        # Check if the PublicIpAddress key exists and has a valid value
        if instance.get("PublicIpAddress") and instance.get("PublicIpAddress") != "N/A":
            failing_resources.append({
                "resource": instance.get("InstanceId", "Unknown ID"),
                "region": instance.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_cloudtrail_cloudwatch_destination_disabled(audit_data):
    """
    Checks if CloudTrail trails have a CloudWatch Logs log group destination enabled.
    """
    failing_resources = []
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        if not trail.get("CloudWatchLogsLogGroupArn"):
            failing_resources.append({
                "resource": trail.get("Name", trail.get("TrailARN")),
                "region": trail.get("HomeRegion", "Unknown Region")
            })
            
    return failing_resources


def check_kms_customer_key_rotation_disabled(audit_data):
    """
    Checks for customer-managed KMS keys that do not have automatic rotation enabled.
    """
    failing_resources = []
    # Safely navigate to the list of KMS keys
    kms_keys = audit_data.get("kms", {}).get("keys", [])

    for key in kms_keys:
        # Check for two conditions: the key is customer-managed AND rotation is disabled
        is_customer_managed = key.get("KeyManager") == "CUSTOMER"
        is_rotation_disabled = key.get("RotationEnabled") == "Disabled"

        if is_customer_managed and is_rotation_disabled:
            # If both conditions are true, add the key to the list of failing resources
            failing_resources.append({
                "resource": key.get("Aliases") or key.get("KeyId", "Unknown ID"),
                "region": key.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_waf_sampled_requests_disabled(audit_data):
    """
    Checks for WAF Web ACLs that do not have Sampled Requests enabled.
    """
    failing_resources = []
    # Safely get the list of Web ACLs
    acls = audit_data.get("waf", {}).get("acls", [])

    for acl in acls:
        # The setting is inside the VisibilityConfig dictionary
        vc_config = acl.get("VisibilityConfig", {})
        if not vc_config.get("SampledRequestsEnabled"):
            failing_resources.append({
                "resource": acl.get("Name", "Unknown ID"),
                "region": acl.get("Region", "Unknown Region")
            })

    return failing_resources

def check_waf_logging_destination_disabled(audit_data):
    """
    Checks for WAF Web ACLs that do not have a full logging destination configured.
    """
    failing_resources = []
    # Safely get the list of Web ACLs from the audit data
    acls = audit_data.get("waf", {}).get("acls", [])

    for acl in acls:
        # Get the logging configuration, defaulting to an empty dictionary
        logging_config = acl.get("LoggingConfiguration", {})
        
        # A disabled logging destination will have no 'LogDestinationConfigs' or it will be an empty list
        if not logging_config.get("LogDestinationConfigs"):
            failing_resources.append({
                "resource": acl.get("Name", "Unknown ID"),
                "region": acl.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ec2_instance_missing_iam_role(audit_data):
    """
    Checks for running EC2 instances that do not have an IAM role associated.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de instancias EC2
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    for instance in ec2_instances:
        # Condición 1: La instancia debe estar en ejecución
        is_running = instance.get("State") == "running"
        
        # Condición 2: El perfil de IAM no debe estar asignado
        has_no_role = not instance.get("IamInstanceProfile") or instance.get("IamInstanceProfile") == "N/A"

        if is_running and has_no_role:
            failing_resources.append({
                "resource": instance.get("InstanceId", "ID Desconocido"),
                "region": instance.get("Region", "Región Desconocida")
            })
            
    return failing_resources

def check_lambda_missing_any_tag(audit_data):
    """
    Checks if any Lambda function has no tags assigned at all.
    """
    failing_resources = []
    lambdas = audit_data.get("compute", {}).get("lambda_functions", [])
    for func in lambdas:
        # The 'Tags' key will be an empty dictionary if no tags are assigned
        if not func.get("Tags"):
            failing_resources.append({
                "resource": func.get("FunctionName"),
                "region": func.get("Region")
            })
    return failing_resources

def check_lambda_using_privileged_role(audit_data):
    """
    Checks for Lambda functions that are using an IAM role identified as privileged.
    """
    failing_resources = []
    
    # 1. Obtener la lista de todos los roles y filtrar solo los privilegiados
    all_roles = audit_data.get("iam", {}).get("roles", [])
    privileged_role_names = {
        role['RoleName'] for role in all_roles if role.get('IsPrivileged')
    }

    # Si no hay roles privilegiados, no hay nada que comprobar
    if not privileged_role_names:
        return []

    # 2. Obtener la lista de funciones Lambda
    lambdas = audit_data.get("compute", {}).get("lambda_functions", [])
    
    # 3. Comprobar cada Lambda
    for func in lambdas:
        role_arn = func.get("Role")
        if role_arn:
            # Extraemos el nombre del rol del ARN (es la última parte)
            role_name = role_arn.split('/')[-1]
            
            # Si el nombre del rol está en nuestra lista de privilegiados, es un hallazgo
            if role_name in privileged_role_names:
                failing_resources.append({
                    "resource": func.get("FunctionName"),
                    "region": func.get("Region")
                })
                
    return failing_resources

def check_cli_mfa_non_compliance(audit_data):
    """
    Verifica si usuarios con acceso CLI no cumplen con los requisitos de MFA.
    Busca usuarios que tienen access keys activas pero no tienen MFA configurado 
    correctamente para acceso programático.
    """
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    
    for user in users:
        # Verificar si el usuario tiene información de compliance MFA CLI
        mfa_compliance = user.get("mfa_compliance")
        if not mfa_compliance:
            continue
            
        # Solo evaluar usuarios que pueden acceder por CLI
        if not mfa_compliance.get("has_active_access_keys"):
            continue
            
        # Si no es CLI compliant, es un hallazgo
        if not mfa_compliance.get("cli_compliant"):
            risk_level = mfa_compliance.get("risk_level", "unknown")
            
            # Crear descripción detallada basada en el tipo de problema
            if risk_level == "critical":
                detail = " (Sin dispositivo MFA)"
            elif risk_level == "high":
                detail = " (Sin política que requiera MFA)"
            else:
                detail = ""
                
            failing_resources.append(f"{user.get('UserName')}{detail}")
    
    return failing_resources


def check_ecr_public_repository(audit_data):
    """
    Checks for ECR repositories that are configured with a public access policy.
    """
    failing_resources = []
    # Safely get the list of repositories from the audit data
    repositories = audit_data.get("ecr", {}).get("repositories", [])

    for repo in repositories:
        # The 'IsPublic' key will be True if the policy allows public access
        if repo.get("IsPublic"):
            failing_resources.append({
                "resource": repo.get("RepositoryName", "Unknown ID"),
                "region": repo.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ecr_image_signing_disabled(audit_data):
    """
    Checks for ECR repositories that do not have image signing enabled.
    """
    failing_resources = []
    repositories = audit_data.get("ecr", {}).get("repositories", [])

    for repo in repositories:
        # 'ImageSigningEnabled' will be False if not configured
        if not repo.get("ImageSigningEnabled"):
            failing_resources.append({
                "resource": repo.get("RepositoryName", "Unknown ID"),
                "region": repo.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ecr_tag_mutability_mutable(audit_data):
    """
    Checks for ECR repositories that are configured with mutable image tags.
    """
    failing_resources = []
    repositories = audit_data.get("ecr", {}).get("repositories", [])

    for repo in repositories:
        # Check if the image tag mutability is set to MUTABLE
        if repo.get("ImageTagMutability") == "MUTABLE":
            failing_resources.append({
                "resource": repo.get("RepositoryName", "Unknown ID"),
                "region": repo.get("Region", "Unknown Region")
            })
            
    return failing_resources


#
# rules.py (Reemplaza la sección de CodePipeline con esto)
#

def _get_codepipeline_pipelines(audit_data):
    """
    Función auxiliar simple y robusta para obtener la lista de pipelines.
    """
    # El backend prepara los datos en audit_data['codepipeline']['pipelines']
    # Usamos .get() para evitar errores si la clave no existiera por alguna razón.
    return audit_data.get("codepipeline", {}).get("pipelines", [])

def check_codepipeline_unencrypted_artifacts(audit_data):
    """Verifica si los pipelines de CodePipeline tienen almacenes de artefactos no cifrados."""
    failing_resources = []
    pipelines = _get_codepipeline_pipelines(audit_data)
    
    for p in pipelines:
        if not p.get("IsEncrypted"):
            failing_resources.append({
                "resource": p.get("Name", "Unknown Pipeline"),
                "region": p.get("Region", "Unknown Region")
            })
    return failing_resources

def check_codepipeline_no_manual_approval(audit_data):
    """Verifica si los pipelines de CodePipeline carecen de una etapa de aprobación manual."""
    failing_resources = []
    pipelines = _get_codepipeline_pipelines(audit_data)
    
    for p in pipelines:
        if not p.get("HasManualApproval"):
            failing_resources.append({
                "resource": p.get("Name", "Unknown Pipeline"),
                "region": p.get("Region", "Unknown Region")
            })
    return failing_resources

def check_codepipeline_no_scan_and_no_inspector(audit_data):
    """Verifica pipelines sin escaneo de seguridad en regiones donde Inspector ECR también está deshabilitado."""
    failing_resources = []
    pipelines = _get_codepipeline_pipelines(audit_data)
    regions_with_inspector = _get_regions_with_inspector_ecr_scan(audit_data) # Esta función auxiliar ya era correcta
    
    for p in pipelines:
        has_scan = p.get("HasSecurityScan", False)
        region = p.get("Region")
        
        if not has_scan and region not in regions_with_inspector:
            failing_resources.append({
                "resource": p.get("Name", "Unknown Pipeline"),
                "region": region or "Unknown Region"
            })
    return failing_resources

def check_codepipeline_no_scan_but_inspector_ok(audit_data):
    """Verifica pipelines sin escaneo de seguridad en regiones donde Inspector ECR está habilitado."""
    failing_resources = []
    pipelines = _get_codepipeline_pipelines(audit_data)
    regions_with_inspector = _get_regions_with_inspector_ecr_scan(audit_data) # Reutilizamos la función
    
    for p in pipelines:
        has_scan = p.get("HasSecurityScan", False)
        region = p.get("Region")
        
        if not has_scan and region in regions_with_inspector:
            failing_resources.append({
                "resource": p.get("Name", "Unknown Pipeline"),
                "region": region or "Unknown Region"
            })
    return failing_resources

# NOTA: La función _get_regions_with_inspector_ecr_scan que ya tenías es correcta.
# Puedes mantenerla como está o usar esta versión ligeramente más limpia si lo prefieres.

def _get_regions_with_inspector_ecr_scan(audit_data):
    """Determina las regiones con escaneo de Inspector ECR activo."""
    try:
        inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
        ecr_repositories = audit_data.get("ecr", {}).get("repositories", [])
        
        regions_with_ecr = {repo.get('Region') for repo in ecr_repositories if repo.get('Region')}
        
        enabled_regions = set()
        for status in inspector_status:
            if status.get('Region') in regions_with_ecr and status.get('ScanECR') == 'ENABLED':
                enabled_regions.add(status.get('Region'))
                
        return enabled_regions
    except Exception as e:
        print(f"[WARNING] Error in _get_regions_with_inspector_ecr_scan: {e}")
        return set()


def _get_regions_with_inspector_ecr_scan(audit_data):
    """
    Helper function mejorada para determinar regiones con Inspector ECR activo.
    También es adaptativa para diferentes estructuras de datos.
    """
    try:
        # Intentar acceso directo primero
        inspector_data = audit_data.get("inspector", {})
        ecr_data = audit_data.get("ecr", {})
        
        # Si no encontramos datos directamente, buscar en results
        if not inspector_data or "scan_status" not in inspector_data:
            for service_key, service_data in audit_data.items():
                if isinstance(service_data, dict) and "results" in service_data:
                    results = service_data["results"]
                    if isinstance(results, dict):
                        if service_key == "inspector" and "scan_status" in results:
                            inspector_data = results
                        elif service_key == "ecr" and "repositories" in results:
                            ecr_data = results
        
        inspector_status = inspector_data.get("scan_status", [])
        ecr_repositories = ecr_data.get("repositories", [])
        
        regions_with_ecr = {repo.get('Region') for repo in ecr_repositories if repo.get('Region')}
        inspector_ecr_scan_status = {
            status.get('Region'): status.get('ScanECR') 
            for status in inspector_status 
            if status.get('Region')
        }
        
        enabled_regions = set()
        for region in regions_with_ecr:
            if inspector_ecr_scan_status.get(region) == 'ENABLED':
                enabled_regions.add(region)
                
        return enabled_regions
        
    except Exception as e:
        print(f"[WARNING] Error in _get_regions_with_inspector_ecr_scan: {e}")
        return set()






def check_ecr_no_scan_on_push_and_no_inspector(audit_data):
    """(MEDIUM Risk) Checks for ECR repos with scan-on-push disabled where Inspector ECR is also disabled."""
    failing_resources = []
    repositories = audit_data.get("ecr", {}).get("repositories", [])
    regions_with_inspector = _get_regions_with_inspector_ecr_scan(audit_data)
    
    for repo in repositories:
        if not repo.get("ScanOnPush") and repo.get("Region") not in regions_with_inspector:
            failing_resources.append({"resource": repo.get("RepositoryName"), "region": repo.get("Region")})
    return failing_resources

def check_ecr_no_scan_on_push_but_inspector_ok(audit_data):
    """(LOW Risk) Checks for ECR repos with scan-on-push disabled where Inspector ECR is enabled."""
    failing_resources = []
    repositories = audit_data.get("ecr", {}).get("repositories", [])
    regions_with_inspector = _get_regions_with_inspector_ecr_scan(audit_data)
    
    for repo in repositories:
        if not repo.get("ScanOnPush") and repo.get("Region") in regions_with_inspector:
            failing_resources.append({"resource": repo.get("RepositoryName"), "region": repo.get("Region")})
    return failing_resources


def check_root_user_console_login(audit_data):
    """
    Verifica si se han detectado eventos de ConsoleLogin con el usuario root en los últimos eventos de CloudTrail.
    El usuario root nunca debería usarse para actividades rutinarias, solo para tareas específicas que requieren acceso root.
    """
    failing_resources = []
    
    # Obtener los eventos de CloudTrail
    cloudtrail_events = audit_data.get("cloudtrail", {}).get("events", [])
    
    if not cloudtrail_events:
        return failing_resources
    
    # Buscar eventos de ConsoleLogin donde el usuario sea "root"
    root_login_events = []
    for event in cloudtrail_events:
        if (event.get("EventName") == "ConsoleLogin" and 
            event.get("Username") == "root"):
            root_login_events.append(event)
    
    # Si encontramos eventos de login del root, añadirlos a los recursos fallidos
    for event in root_login_events:
        event_time = event.get("EventTime", "Unknown time")
        source_ip = event.get("SourceIPAddress", "Unknown IP")
        region = event.get("EventRegion", "Unknown region")
        
        # Crear un identificador único para el evento
        event_identifier = f"Root login at {event_time} from IP {source_ip}"
        
        failing_resources.append({
            "resource": event_identifier,
            "region": region
        })
    
    return failing_resources

def check_root_mfa_disabled(audit_data):
    """
    Verifica si el usuario root no tiene MFA habilitado.
    """
    failing_resources = []
    password_policy = audit_data.get("iam", {}).get("password_policy", {})
    
    # Verificar si hay información de estado del MFA del root
    root_mfa_status = password_policy.get("RootMFAStatus", {})
    
    # Si hay un error al verificar, no podemos determinar el estado
    if root_mfa_status.get("error"):
        return failing_resources
    
    # Si el MFA del root está deshabilitado, es un hallazgo crítico
    if root_mfa_status.get("root_mfa_enabled") is False:
        failing_resources.append({
            "resource": "Root User Account",
            "region": "Global"
        })
    
    return failing_resources


def check_root_mfa_not_hardware(audit_data):
    """
    Verifica si el usuario root tiene MFA habilitado pero no es hardware.
    Solo evalúa cuando el MFA está habilitado.
    """
    failing_resources = []
    password_policy = audit_data.get("iam", {}).get("password_policy", {})
    
    # Verificar si hay información de estado del MFA del root
    root_mfa_status = password_policy.get("RootMFAStatus", {})
    
    # Si hay un error al verificar o MFA está deshabilitado, no evaluar esta regla
    if root_mfa_status.get("error") or not root_mfa_status.get("root_mfa_enabled"):
        return failing_resources
    
    # Solo verificar el tipo si el check de IAM.6 está disponible
    if not root_mfa_status.get("iam6_check_available"):
        return failing_resources
    
    # Si el MFA está habilitado pero no es hardware, es un hallazgo medio
    if root_mfa_status.get("mfa_is_hardware") is False:
        failing_resources.append({
            "resource": "Root User MFA Configuration",
            "region": "Global"
        })
    
    return failing_resources

def check_s3_public_buckets(audit_data):
    """
    Verifica si existen buckets de S3 que son públicamente accesibles.
    """
    failing_resources = []
    
    # Obtener los datos de exposición donde están los buckets públicos
    exposure_data = audit_data.get("exposure", {})
    
    # Los buckets públicos están en exposure_data["details"]["S3 Public Buckets"]
    s3_public_buckets = exposure_data.get("details", {}).get("S3 Public Buckets", {})
    
    # Iterar sobre todas las regiones que contengan buckets públicos
    for region, buckets in s3_public_buckets.items():
        for bucket_name in buckets:
            failing_resources.append({
                "resource": bucket_name,
                "region": "Global"  # S3 es un servicio global, aunque técnicamente los buckets tienen región
            })
    
    return failing_resources

def check_secrets_rotation_disabled(audit_data):
    """
    Verifica secretos sin rotación automática habilitada, especialmente crítico para credenciales de base de datos.
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        if not secret.get("RotationEnabled"):
            failing_resources.append({
                "resource": secret.get("Name"),
                "region": secret.get("Region")
            })
    return failing_resources

def check_secrets_aws_managed_kms(audit_data):
    """
    Verifica secretos que usan claves KMS gestionadas por AWS en lugar de claves gestionadas por el cliente.
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        kms_key = secret.get("KmsKeyId", "")
        if not kms_key or "alias/aws/secretsmanager" in kms_key:
            failing_resources.append({
                "resource": secret.get("Name"),
                "region": secret.get("Region")
            })
    return failing_resources

def check_secrets_public_resource_policy(audit_data):
    """
    Verifica secretos con políticas de recursos que permiten acceso público o demasiado permisivo.
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        
        resource_policy = secret.get("ResourcePolicy")
        if resource_policy and isinstance(resource_policy, dict):
            for statement in resource_policy.get("Statement", []):
                principal = statement.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    failing_resources.append({
                        "resource": secret.get("Name"),
                        "region": secret.get("Region")
                    })
                    break
    return failing_resources

def check_secrets_no_replication(audit_data):
    """
    Verifica secretos críticos sin replicación para recuperación ante desastres.
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        
        replication_status = secret.get("ReplicationStatus", [])
        if not replication_status:
            failing_resources.append({
                "resource": secret.get("Name"),
                "region": secret.get("Region")
            })
    return failing_resources

def check_secrets_no_tags(audit_data):
    """
    Verifica secretos sin etiquetas para clasificación y gobierno.
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        if not secret.get("Tags"):
            failing_resources.append({
                "resource": secret.get("Name"),
                "region": secret.get("Region")
            })
    return failing_resources

def check_secrets_long_rotation_interval(audit_data):
    """
    Verifica secretos con intervalos de rotación excesivamente largos (>90 días).
    """
    failing_resources = []
    secrets = audit_data.get("secretsManager", {}).get("secrets", [])
    
    for secret in secrets:
        if secret.get("Error"):
            continue
        if not secret.get("RotationEnabled"):
            continue
            
        rotation_rules = secret.get("RotationRules", {})
        interval = rotation_rules.get("AutomaticallyAfterDays", 0)
        if interval > 90:
            failing_resources.append({
                "resource": f"{secret.get('Name')} ({interval} days)",
                "region": secret.get("Region")
            })
    return failing_resources


# Coloca esta función en la sección 2, junto a las otras funciones de chequeo.

def check_unused_iam_users(audit_data):
    """
    Verifica si existen usuarios de IAM que no han tenido actividad (login en consola o uso de access key)
    en los últimos 90 días.
    """
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    ninety_days = timedelta(days=90)
    now = datetime.now(timezone.utc)

    for user in users:
        last_activity = None

        # 1. Comprobar la última vez que se usó la contraseña
        if user.get("PasswordLastUsed"):
            try:
                password_used_date = datetime.fromisoformat(user["PasswordLastUsed"])
                last_activity = password_used_date
            except (ValueError, TypeError):
                pass  # Ignorar si la fecha es inválida

        # 2. Comprobar la última vez que se usó cada clave de acceso
        for key in user.get("AccessKeys", []):
            if key.get("AccessKeyLastUsed"):
                try:
                    key_used_date = datetime.fromisoformat(key["AccessKeyLastUsed"])
                    # Actualizar si esta actividad es más reciente
                    if last_activity is None or key_used_date > last_activity:
                        last_activity = key_used_date
                except (ValueError, TypeError):
                    continue
        
        # 3. Evaluar la inactividad
        # Si nunca hubo actividad (last_activity es None) y el usuario tiene más de 90 días, se considera inactivo.
        # O si la última actividad fue hace más de 90 días.
        if last_activity:
            if (now - last_activity) > ninety_days:
                failing_resources.append(user.get("UserName"))
        else:
            # Si no hay registro de actividad, comprobamos la fecha de creación del usuario.
            # Un usuario recién creado sin actividad no debería ser marcado como inactivo.
            try:
                create_date = datetime.fromisoformat(user.get("CreateDate"))
                if (now - create_date) > ninety_days:
                    failing_resources.append(user.get("UserName"))
            except (ValueError, TypeError):
                # Si no podemos determinar la fecha de creación, lo añadimos por seguridad
                failing_resources.append(user.get("UserName"))

    return failing_resources

def check_lambda_hardcoded_credentials(audit_data):
    """
    Verifica si existen funciones Lambda con credenciales hardcodeadas en variables de entorno
    o patrones sospechosos que indiquen almacenamiento inseguro de secretos.
    """
    failing_resources = []
    
    # Obtener los hallazgos de credential harvesting del módulo exposure
    lambda_credentials = []
    
    if "exposure" in audit_data:
        exposure_data = audit_data["exposure"]
        if isinstance(exposure_data, dict) and "lambda_credentials" in exposure_data:
            lambda_credentials = exposure_data["lambda_credentials"]
    
    # Filtrar hallazgos relevantes para credenciales hardcodeadas
    for credential_finding in lambda_credentials:
        severity = credential_finding.get("severity", "")
        finding_type = credential_finding.get("type", "")
        
        # Incluir tipos específicos que indican credenciales hardcodeadas o sospechosas
        is_credential_related = any([
            "Suspicious Environment Variable Name" in finding_type,
            "Potential Hardcoded Credential" in finding_type,
            "Hardcoded" in finding_type.lower(),
            "credential" in finding_type.lower()
        ])
        
        # Solo incluir hallazgos de severidad alta/crítica relacionados con credenciales
        if severity in ["CRITICAL", "HIGH"] and is_credential_related:
            function_name = credential_finding.get("function_name", "Unknown Function")
            region = credential_finding.get("region", "Unknown Region")
            env_var_name = credential_finding.get("env_var_name", "")
            
            # Crear descripción detallada del hallazgo
            if env_var_name:
                resource_description = f"{function_name} (Variable: {env_var_name})"
            else:
                resource_description = function_name
            
            failing_resources.append({
                "resource": resource_description,
                "region": region
            })
    
    return failing_resources

def check_waf_classic_in_use(audit_data):
    """
    Verifica si se está utilizando alguna Web ACL de AWS WAF Classic (v1).
    """
    # Navega de forma segura hasta la lista de ACLs
    acls = audit_data.get("waf", {}).get("acls", [])
    
    # Itera sobre cada ACL para comprobar su versión
    for acl in acls:
        if acl.get("Version") == "Classic":
            # Si encontramos al menos una, la condición se cumple para toda la cuenta.
            # No es necesario seguir buscando.
            return [{"resource": "Uso de AWS WAF Classic", "region": "Global"}]
            
    # Si el bucle termina sin encontrar ninguna ACL clásica, no hay hallazgos.
    return []

# ------------------------------------------------------------------------------
# 3. Master Rule List
# ------------------------------------------------------------------------------
COVERAGE_SERVICES = ("acm", "inspector", "databases")


def coverage_gaps(audit_data, data_sources):
    gaps = []
    for source in data_sources:
        if source not in COVERAGE_SERVICES:
            continue
        collection = (audit_data.get(source) or {}).get("_collection")
        if collection is None:
            continue
        status = collection.get("status", "unknown")
        coverage_known = collection.get("coverageKnown", False)
        if status in ("partial", "failed", "unknown") or not coverage_known:
            failed_units = [
                {key: unit.get(key) for key in ("operation", "region", "category")}
                for unit in collection.get("units", [])
                if unit.get("status") == "failed"
            ][:10]
            gaps.append({"service": source, "status": status,
                         "coverageKnown": coverage_known, "failedUnits": failed_units})
    return gaps


RULES_TO_CHECK = [
    {
        "rule_id": "IAM_001",
        "section": "Identity & Access",
        "name": "User without MFA enabled",
        "severity": SEVERITY["HIGH"],
        "description": "An IAM user does not have Multi-Factor Authentication (MFA) enabled. Requiring MFA for all users is a fundamental security best practice to add an extra layer of protection against unauthorized access.",
        "remediation": "Navigate to the IAM service in the AWS console, select the affected user, and on the 'Security credentials' tab, assign an MFA device.",
        "pci_requirement": "PCI DSS 8.4",
        "check_function": check_mfa_for_all_users
    },
    {
        "rule_id": "IAM_002",
        "section": "Identity & Access",
        "name": "Access Key older than 90 days",
        "severity": SEVERITY["MEDIUM"],
        "description": "Programmatic access keys older than 90 days exist. It is a security best practice to rotate credentials regularly to limit the risk in case a key is compromised.",
        "remediation": "In the IAM console, create a new access key for the user, update the applications that use it, and then deactivate and delete the old key.",
        "pci_requirement": "PCI DSS 8.3.9",
        "check_function": check_iam_access_key_age
    },
    {
        "rule_id": "IAM_003",
        "section": "Identity & Access",
        "name": "Password policy is not strong enough",
        "severity": SEVERITY["HIGH"],
        "description": "The account's password policy does not meet recommended security standards, making user accounts more vulnerable to brute-force or guessing attacks.",
        "remediation": "In the IAM console, go to 'Account settings' and edit the password policy to meet all requirements: length >= 12, use of uppercase, lowercase, numbers, and symbols, expiration <= 90 days, reuse prevention >= 4, and hard expiry.",
        "pci_requirement": "PCI DSS 8.3.6",
        "check_function": check_password_policy_strength
    },
    {
        "rule_id": "IAM_004",
        "section": "Identity & Access",
        "name": "User with directly attached policies",
        "severity": SEVERITY["LOW"],
        "description": "A user has been detected with one or more IAM policies attached directly to their identity. AWS best practice recommends managing permissions through groups and roles to simplify administration and reduce the risk of configuration errors.",
        "remediation": "Create an IAM group that represents the user's role, attach the necessary policies to that group, and then add the user to the group. Finally, remove the policies that are directly attached to the user.",
        "pci_requirement": "PCI DSS 7.2.1",
        "check_function": check_user_has_attached_policies
    },
    {
        "rule_id": "IAM_005",
        "section": "Identity & Access",
        "name": "User with CLI access does not comply with MFA requirements",
        "severity": SEVERITY["HIGH"],
        "description": "An IAM user with active access keys (CLI/programmatic access) does not properly comply with MFA requirements. This could be because the user lacks an MFA device entirely, or because there are no IAM policies enforcing MFA authentication for API calls. Without proper MFA enforcement for CLI access, the account is vulnerable to credential theft and unauthorized programmatic access.",
        "remediation": "For users without MFA devices: Enable MFA in the IAM console under 'Security credentials'. For users without MFA enforcement policies: Create or attach an IAM policy that includes a condition requiring 'aws:MultiFactorAuthPresent' to be true for sensitive actions. Consider using STS GetSessionToken with MFA for temporary credentials in CLI workflows.",
        "pci_requirement": "PCI DSS 8.4",
        "check_function": check_cli_mfa_non_compliance
    },
    {
        "rule_id": "IAM_006",
        "section": "Identity & Access",
        "name": "Root user does not have MFA enabled",
        "severity": SEVERITY["CRITICAL"],
        "description": "The root user account does not have Multi-Factor Authentication (MFA) enabled. The root user has complete access to all AWS services and resources in the account. Without MFA, if the root user credentials are compromised, an attacker would have unrestricted access to the entire AWS account, potentially leading to complete account takeover, data breaches, and significant financial losses.",
        "remediation": "Immediately enable MFA for the root user account. Go to the AWS Console, sign in as root, navigate to 'My Security Credentials', and assign an MFA device. Use a hardware MFA device for the highest level of security. After enabling MFA, avoid using the root user for daily operations - create IAM users with appropriate permissions instead.",
        "pci_requirement": "PCI DSS 8.4",
        "check_function": check_root_mfa_disabled
    },
    {
        "rule_id": "IAM_007",
        "section": "Identity & Access", 
        "name": "Root user MFA is not hardware-based",
        "severity": SEVERITY["MEDIUM"],
        "description": "The root user has MFA enabled, but it appears to be using a virtual MFA device rather than a hardware-based device. While virtual MFA provides good security, hardware MFA devices offer additional protection against sophisticated attacks such as SIM swapping, malware on mobile devices, or social engineering attacks targeting virtual MFA applications. For the root user, which has the highest level of access, hardware MFA provides the strongest possible authentication.",
        "remediation": "Replace the current virtual MFA device with a hardware MFA device. Purchase a compatible hardware MFA device (such as a FIDO2/WebAuthn security key or an OATH-TOTP hardware token), then go to the AWS Console root user security credentials section to remove the current virtual MFA device and configure the new hardware device.",
        "pci_requirement": "PCI DSS 8.5.1",
        "check_function": check_root_mfa_not_hardware
    },
    {
        "rule_id": "IAM_008",
        "section": "Identity & Access", 
        "name": "Unused IAM user detected",
        "severity": SEVERITY["LOW"],
        "description": "An IAM user account has shown no activity (no console login or API key usage) for over 90 days. Inactive accounts increase the attack surface, as their credentials could be compromised and used by an attacker without being noticed. Regular review and deactivation of inactive accounts is a critical security hygiene practice.",
        "remediation": "Review the identified inactive user accounts. If the user no longer requires access, deactivate or delete the IAM user. If access is still required, ensure the user's credentials are secure and understand why the account has been inactive. This helps maintain the principle of least privilege and reduces security risks.",
        "pci_requirement": "PCI DSS 8.1.4",
        "check_function": check_unused_iam_users
    },
    {
        "rule_id": "GUARDDUTY_001",
        "section": "Security Services",
        "name": "GuardDuty not enabled in some regions",
        "severity": SEVERITY["LOW"],
        "description": "AWS GuardDuty, the threat detection service, is not enabled or is suspended in one or more regions. Enabling it is key to detecting malicious or unauthorized activity in the account.",
        "remediation": "Access the AWS console, go to the GuardDuty service, and enable it in the indicated regions to improve your account's threat detection.",
        "pci_requirement": "PCI DSS 11.5.1",
        "check_function": check_guardduty_disabled
    },
    {
        "rule_id": "GUARDDUTY_002",
        "section": "Security Services",
        "name": "GuardDuty Malware Protection disabled with EC2 instances present",
        "severity": SEVERITY["LOW"],
        "description": "GuardDuty Malware Protection is disabled in a region where EC2 instances exist. Although GuardDuty is active, this specific feature adds a layer of protection to detect malicious software on EC2 workloads and should be enabled if these instances are used.",
        "remediation": "Access the GuardDuty console, go to the detector settings for the affected region, and enable the 'Malware Protection' feature. This has no additional cost unless malware is detected and a scan is initiated.",
        "pci_requirement": "PCI DSS 5.2.1",
        "check_function": check_guardduty_malware_protection_disabled_with_ec2
    },
    {
        "rule_id": "CONFIG_001",
        "section": "Security Services",
        "name": "AWS Config not enabled in some regions",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Config is not enabled in one or more regions. This service is essential for auditing and evaluating the configurations of AWS resources, allowing for continuous compliance monitoring.",
        "remediation": "Access the AWS console, go to the AWS Config service, and enable it in the indicated regions to improve visibility and configuration compliance of your resources.",
        "pci_requirement": "PCI DSS 11.5.2",
        "check_function": check_config_disabled
    },
    {
        "rule_id": "SECURITYHUB_001",
        "section": "Security Services",
        "name": "AWS Security Hub not enabled in some regions",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Security Hub is not enabled in one or more regions. Security Hub provides a comprehensive view of high-priority security alerts and compliance status across all AWS services.",
        "remediation": "Access the AWS console, go to the Security Hub service, and enable it in the indicated regions to centralize and manage your account's security posture.",
        "pci_requirement": "PCI DSS 2.2.6",
        "check_function": check_security_hub_disabled
    },
    {
        "rule_id": "SECURITYHUB_002",
        "section": "Security Services",
        "name": "Security Hub Standard PCI DSS 3.2.1 not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'PCI DSS v3.2.1' security standard is not enabled in AWS Security Hub. If the account processes, stores, or transmits credit card data, enabling this standard is crucial for monitoring compliance with the required security controls.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'PCI DSS v3.2.1' standard.",
        "pci_requirement": "PCI DSS 2.2.6",
        "check_function": check_pci_dss_3_2_1_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_003",
        "section": "Security Services",
        "name": "Security Hub Standard PCI DSS 4.0.1 not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'PCI DSS v4.0.1' security standard is not enabled in AWS Security Hub. If the account processes, stores, or transmits credit card data, enabling this standard is crucial for monitoring compliance with the required security controls.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'PCI DSS v4.0.1' standard.",
        "pci_requirement": "PCI DSS 2.2.6",
        "check_function": check_pci_dss_4_0_1_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_004",
        "section": "Security Services",
        "name": "CIS AWS Foundations Benchmark v1.2.0 Standard not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'CIS AWS Foundations Benchmark v1.2.0' security standard is not enabled in Security Hub. This benchmark provides a set of security recommendations for configuring AWS and helps align the account with industry best practices.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'CIS AWS Foundations Benchmark v1.2.0' standard.",
        "pci_requirement": "PCI DSS 2.2.6",
        "check_function": check_cis_1_2_0_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_005",
        "section": "Security Services",
        "name": "AWS Foundational Security Best Practices Standard not enabled",
        "severity": SEVERITY["HIGH"],
        "description": "The 'AWS Foundational Security Best Practices' standard is not enabled in Security Hub. This is the primary AWS standard that helps detect when accounts and resources deviate from security best practices. It is essential to have it activated.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'AWS Foundational Security Best Practices v1.0.0' standard.",
        "pci_requirement": "PCI DSS 2.2.6",
        "check_function": check_aws_foundational_security_standard_enabled
    },
    {
        "rule_id": "INSPECTOR_001",
        "section": "Vulnerability Management",
        "name": "Resource with End of Life (EOL) platform",
        "severity": SEVERITY["CRITICAL"],
        "description": "A resource (such as an EC2 instance) has been detected using an operating system or platform that has reached its 'End of Life' (EOL). This means it no longer receives security updates from the provider, leaving it exposed to known and future vulnerabilities.",
        "remediation": "Migrate the application or service to an instance with a supported operating system or platform that receives security updates. Plan to upgrade resources before they reach their EOL date.",
        "pci_requirement": "PCI DSS 6.3.1",
        "data_sources": ['inspector'],
        "check_function": check_inspector_platform_eol
    },
    {
        "rule_id": "INSPECTOR_002",
        "section": "Vulnerability Management",
        "name": "Inspector EC2 scanning disabled in region with instances",
        "severity": SEVERITY["MEDIUM"],
        "description": "EC2 instances have been detected in a region where Amazon Inspector vulnerability scanning for EC2 is not activated. This represents a security blind spot, as new vulnerabilities in these instances will not be discovered.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Amazon EC2 scanning' is activated for the affected region.",
        "pci_requirement": "PCI DSS 11.3.1",
        "data_sources": ['inspector'],
        "check_function": check_inspector_ec2_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_003",
        "section": "Vulnerability Management",
        "name": "Inspector Lambda scanning disabled in region with functions",
        "severity": SEVERITY["MEDIUM"],
        "description": "Lambda functions have been detected in a region where Amazon Inspector vulnerability scanning for Lambda is not activated. This can leave your functions' code and dependencies unscanned for known vulnerabilities.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Lambda functions scanning' is activated for the affected region.",
        "pci_requirement": "PCI DSS 11.3.1",
        "data_sources": ['inspector'],
        "check_function": check_inspector_lambda_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_004",
        "section": "Vulnerability Management",
        "name": "Inspector ECR scanning disabled in region with repositories",
        "severity": SEVERITY["MEDIUM"],
        "description": "ECR repositories have been detected in a region where Amazon Inspector container image scanning is not activated. Images can contain vulnerabilities in their operating system or software packages, and not scanning them represents a significant security risk.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Amazon ECR scanning' is activated for the affected region.",
        "pci_requirement": "PCI DSS 11.3.1",
        "data_sources": ['inspector', 'ecr'],
        "check_function": check_inspector_ecr_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_005",
        "section": "Vulnerability Management",
        "name": "Critical or High vulnerability unpatched for over 30 days",
        "severity": SEVERITY["HIGH"],
        "description": "Inspector findings with 'Critical' or 'High' severity have been detected that have not been remediated in over 30 days. This represents a significant and prolonged security risk, indicating a potential gap in the vulnerability and patch management process.",
        "remediation": "Immediately prioritize and remediate these old findings. Review your patch management processes to ensure high-impact vulnerabilities are addressed within an acceptable timeframe (SLA).",
        "pci_requirement": "PCI DSS 6.3.3",
        "data_sources": ['inspector'],
        "check_function": check_inspector_old_critical_findings
    },
    {
        "rule_id": "CLOUDTRAIL_001",
        "section": "Logging & Monitoring",
        "name": "Region without a defined CloudTrail trail",
        "severity": SEVERITY["MEDIUM"],
        "description": "An AWS region has been detected that does not have any CloudTrail trail defined. Having an audit log of all API calls in every region is a fundamental security practice for incident investigation and activity monitoring.",
        "remediation": "Create a CloudTrail trail in the affected region. It is highly recommended to create a multi-region trail from the primary region to consolidate logs from all regions into a single S3 bucket.",
        "pci_requirement": "PCI DSS 10.2.1",
        "check_function": check_no_cloudtrail_in_region
    },
    {
        "rule_id": "CLOUDTRAIL_002",
        "section": "Logging & Monitoring",
        "name": "CloudTrail trail without KMS encryption enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "A CloudTrail trail has been detected that does not use AWS KMS encryption to protect the log files. Encrypting logs at rest is a fundamental security practice to protect sensitive audit information from unauthorized access if the S3 bucket is compromised.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the storage section, enable log data encryption with AWS KMS, using either an AWS-managed key or a customer-managed key (CMK).",
        "pci_requirement": "PCI DSS 10.3.2",
        "check_function": check_cloudtrail_kms_encryption_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_003",
        "section": "Logging & Monitoring",
        "name": "CloudTrail log file integrity validation disabled",
        "severity": SEVERITY["HIGH"],
        "description": "A CloudTrail trail has been detected that does not have log file integrity validation enabled. This feature is crucial to ensure that logs have not been altered or deleted after being delivered to the S3 bucket. Without it, the reliability of the audit records cannot be guaranteed.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the 'Storage properties' section, ensure that the 'Enable log file integrity validation' option is checked.",
        "pci_requirement": "PCI DSS 10.3.4",
        "check_function": check_cloudtrail_log_file_validation_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_004",
        "section": "Logging & Monitoring",
        "name": "CloudTrail trail without CloudWatch Logs destination",
        "severity": SEVERITY["MEDIUM"],
        "description": "A CloudTrail trail has been detected that does not have a CloudWatch Logs destination configured. This prevents the ability to create metric filters and alarms for real-time monitoring of critical API calls, such as root user logins, security group changes, or unauthorized API activity.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the 'CloudWatch Logs' section, enable the option and either create a new log group or select an existing one to send the logs to.",
        "pci_requirement": "PCI DSS 10.4",
        "check_function": check_cloudtrail_cloudwatch_destination_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_005",
        "section": "Identity & Access",
        "name": "Root user console login detected",
        "severity": SEVERITY["HIGH"],
        "description": "Console login events have been detected using the AWS root user account. The root user has complete access to all AWS services and resources in the account and should only be used for specific account management tasks that require root access. Regular use of the root user for daily operations represents a significant security risk and violates AWS security best practices.",
        "remediation": "Investigate the necessity of the root user login. If it was for legitimate account management tasks, ensure MFA is enabled for the root user. For regular operations, create IAM users with appropriate permissions instead. Consider implementing CloudWatch alarms for root user activity monitoring and establish processes that minimize root user usage.",
        "pci_requirement": "PCI DSS 10.3.2",
        "check_function": check_root_user_console_login
    },
    {
        "rule_id": "CONNECTIVITY_001",
        "section": "Network & Connectivity",
        "name": "Network segmentation review recommended",
        "severity": SEVERITY["INFO"],
        "description": "The use of advanced network components such as VPC Peering, Transit Gateway, VPNs, or VPC Endpoints has been detected. These services indicate a complex network architecture that interconnects different environments. It is a good practice to perform network segmentation tests to ensure that the isolation between VPCs and on-premises networks is as expected and that no unintended communication paths exist.",
        "remediation": "Plan and execute a network segmentation test. Verify that only explicitly permitted traffic flows are possible between the different network segments (e.g., development, pre-production, production) and with corporate networks.",
        "pci_requirement": "PCI DSS 11.4.5",
        "check_function": check_network_connectivity_exists
    },
    {
        "rule_id": "DB_001",
        "section": "Network & Connectivity",
        "name": "RDS instance with public access",
        "severity": SEVERITY["HIGH"],
        "description": "An RDS database instance has been detected that is configured to be publicly accessible from the Internet. This exposes the database to direct attacks, such as brute-force attempts, SQL injection, or vulnerability exploitation, and significantly increases the risk of a data breach.",
        "remediation": "Navigate to the RDS console, select the affected instance, and click 'Modify'. In the 'Connectivity' section, change the 'Public access' option from 'Yes' to 'No'. Ensure that your resources within the VPC (such as EC2 instances or Lambda functions) have the necessary network connectivity to access the database privately.",
        "pci_requirement": "PCI DSS 1.4.4",
        "data_sources": ['databases'],
        "check_function": check_rds_publicly_accessible
    },
    {
        "rule_id": "DB_002",
        "section": "Data Protection",
        "name": "RDS instance is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "An RDS database instance has been detected that does not have storage encryption enabled. This is a critical security gap, especially for PCI DSS compliance, as it leaves sensitive data unprotected on the underlying storage.",
        "remediation": "Encryption must be enabled at the time of instance creation. To remediate this, create a snapshot of the unencrypted instance, copy the snapshot while enabling encryption on the copy, and finally, restore the database from the new encrypted snapshot.",
        "pci_requirement": "PCI DSS 3.5.1",
        "data_sources": ['databases'],
        "check_function": check_rds_instance_unencrypted
    },
    {
        "rule_id": "DB_003",
        "section": "Data Protection",
        "name": "Aurora cluster is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "An Aurora database cluster has been detected that does not have storage encryption enabled. As with RDS, this is a critical risk that exposes data to unauthorized access at the disk level.",
        "remediation": "Encryption for an Aurora cluster is defined at the time of its creation. To fix this finding, it is necessary to create a new cluster with encryption enabled and migrate the data from the unencrypted cluster.",
        "pci_requirement": "PCI DSS 3.5.1",
        "data_sources": ['databases'],
        "check_function": check_aurora_cluster_unencrypted
    },
    {
        "rule_id": "DB_004",
        "section": "Data Protection",
        "name": "DynamoDB table is not encrypted with a managed key",
        "severity": SEVERITY["HIGH"],
        "description": "A DynamoDB table has been detected that does not use encryption at rest with a customer-managed key (CMK) or an AWS-managed key (KMS). Although DynamoDB encrypts data by default, using KMS keys provides an additional layer of control and auditability.",
        "remediation": "In the DynamoDB console, select the table, go to the 'Additional settings' tab, and in the 'Encryption at rest' section, change the encryption key to an AWS-managed (KMS) or customer-managed (CMK) key.",
        "pci_requirement": "PCI DSS 3.5.1",
        "data_sources": ['databases'],
        "check_function": check_dynamodb_table_unencrypted
    },
    {
        "rule_id": "DB_005",
        "section": "Data Protection",
        "name": "DocumentDB cluster is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "A DocumentDB cluster has been detected that does not have storage encryption enabled. This is a critical security risk, as the data on the disk is not protected against unauthorized access.",
        "remediation": "Encryption for DocumentDB must be enabled during cluster creation and cannot be changed afterward. Remediation involves creating a new cluster with encryption enabled and migrating the data.",
        "pci_requirement": "PCI DSS 3.5.1",
        "data_sources": ['databases'],
        "check_function": check_docdb_cluster_unencrypted
    },
    {
        "rule_id": "EXPOSURE_001",
        "section": "Internet Exposure",
        "name": "Load Balancer with outdated TLS Policy",
        "severity": SEVERITY["HIGH"],
        "description": "A public load balancer (ALB/NLB) has been detected whose HTTPS/TLS listener allows the use of outdated TLS versions (TLS 1.0 or TLS 1.1). These protocols have known vulnerabilities (such as POODLE and BEAST) and do not support modern encryption algorithms, exposing traffic to potential interception and decryption attacks.",
        "remediation": "Navigate to the EC2 console -> Load Balancers. Select the affected listener and edit its configuration to assign a modern security policy that requires at least TLSv1.2, such as 'ELBSecurityPolicy-TLS-1-2-2017-01' or a later version.",
        "pci_requirement": "PCI DSS 4.2.1",
        "check_function": check_alb_outdated_tls_policy
    },
    {
        "rule_id": "EXPOSURE_002",
        "section": "Internet Exposure",
        "name": "EC2 instance with a public IP address",
        "severity": SEVERITY["MEDIUM"],
        "description": "An EC2 instance has been detected with a public IP address, making it directly accessible from the Internet. This increases the attack surface, exposing it to scans, brute-force attacks, and exploitation of unpatched vulnerabilities.",
        "remediation": "Review if the instance requires direct public access. If not, disassociate the Elastic IP or modify the subnet settings to prevent auto-assignment of public IPs. If public access is necessary, ensure its Security Group is highly restrictive, allowing traffic only from trusted sources on the required ports.",
        "pci_requirement": "PCI DSS 1.3.1",
        "check_function": check_ec2_publicly_exposed
    },
    {
        "rule_id": "ACM_001",
        "section": "Security Services",
        "name": "Expired ACM certificate detected",
        "severity": SEVERITY["HIGH"],
        "description": "A certificate managed by AWS Certificate Manager (ACM) has been detected that has expired. Expired certificates cause trust errors in browsers and can disrupt service for applications that use them.",
        "remediation": "Navigate to the ACM console, locate the affected certificate by its domain name, and proceed to renew it. If the certificate is no longer in use, delete it to avoid alerts.",
        "pci_requirement": "PCI DSS 4.2.1",
        "data_sources": ['acm'],
        "check_function": check_acm_expired_certificates
    },
    {
        "rule_id": "KMS_001",
        "section": "Data Protection",
        "name": "Customer Managed KMS Key with Rotation Disabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "A customer-managed KMS key (CMK) has been detected without automatic key rotation enabled. Regularly rotating keys is a security best practice that limits the potential impact of a compromised key and reduces the amount of data protected by a single encryption key version.",
        "remediation": "Navigate to the KMS console, select the affected key, and go to the 'Key rotation' tab. Check the box to enable automatic key rotation. AWS will then automatically generate new key material every year.",
        "pci_requirement": "PCI DSS 3.7.4",
        "check_function": check_kms_customer_key_rotation_disabled
    },
    {
        "rule_id": "ECR_001",
        "section": "Vulnerability Management",
        "name": "ECR repository with mutable image tags",
        "severity": SEVERITY["LOW"],
        "description": "An ECR repository allows image tags to be overwritten. This practice goes against the principle of immutability and can lead to confusion in deployments, making it difficult to track which version of an image is running. In a worst-case scenario, a malicious image could be pushed with a production tag.",
        "remediation": "Navigate to the ECR console, select the repository, and edit its settings to change 'Tag immutability' to 'Immutable'. This ensures that once an image tag is pushed, it cannot be modified.",
        "pci_requirement": "PCI DSS 11.5.2",
        "check_function": check_ecr_tag_mutability_mutable
    },
    {
        "rule_id": "ECR_002",
        "section": "Vulnerability Management",
        "name": "ECR repository is publicly accessible",
        "severity": SEVERITY["LOW"],
        "description": "An ECR repository has a resource-based policy that grants public access. This allows any user on the internet to pull images, potentially exposing proprietary code or vulnerable container images.",
        "remediation": "Navigate to the ECR console, select the repository, and under 'Permissions', edit the policy to remove any statements that grant access to a public principal ('*').",
        "pci_requirement": "PCI DSS 1.3.1",
        "check_function": check_ecr_public_repository
    },
    {
        "rule_id": "ECR_003",
        "section": "Vulnerability Management",
        "name": "ECR repository with image signing disabled",
        "severity": SEVERITY["LOW"],
        "description": "An ECR repository does not have an image signing configuration. Image signing ensures the authenticity and integrity of container images, confirming they are from a trusted source and have not been tampered with.",
        "remediation": "Configure AWS Signer with a signing profile for container images and integrate it with your CI/CD pipeline to sign images before they are pushed to ECR. Enforce policies that only allow signed images to be deployed.",
        "pci_requirement": "PCI DSS 11.5.2",
        "check_function": check_ecr_image_signing_disabled
    },
        {
        "rule_id": "ECR_004",
        "section": "Vulnerability Management",
        "name": "ECR repo with scan on push disabled and no compensating control",
        "severity": SEVERITY["MEDIUM"],
        "description": "An ECR repository does not automatically scan images for vulnerabilities, and Amazon Inspector is also not configured to scan ECR images in this region. This creates a critical security gap, as there is no automated mechanism to detect vulnerabilities in container images.",
        "remediation": "The highest priority is to enable 'Scan on push' in the ECR repository settings. As a secondary control, enable Amazon Inspector for ECR in the region.",
        "pci_requirement": "PCI DSS 6.2.3",
        "data_sources": ['ecr', 'inspector'],
        "check_function": check_ecr_no_scan_on_push_and_no_inspector
    },
    {
        "rule_id": "ECR_005",
        "section": "Vulnerability Management",
        "name": "ECR repo with scan on push disabled but Inspector is active",
        "severity": SEVERITY["LOW"],
        "description": "An ECR repository does not use the basic 'Scan on push' feature. However, Amazon Inspector is active for ECR in this region, which acts as a compensating control by providing advanced vulnerability scanning. While this is a better configuration, enabling 'Scan on push' is still recommended for immediate feedback.",
        "remediation": "Enable 'Scan on push' in the ECR repository settings to get immediate vulnerability feedback upon pushing an image.",
        "pci_requirement": "PCI DSS 6.2.3",
        "data_sources": ['ecr', 'inspector'],
        "check_function": check_ecr_no_scan_on_push_but_inspector_ok
    },
    {
        "rule_id": "CODEPIPELINE_001",
        "section": "CI/CD Security",
        "name": "CodePipeline artifact store is not encrypted",
        "severity": SEVERITY["LOW"],
        "description": "A CodePipeline is using an artifact store (S3 bucket) that does not have encryption enabled. This could expose source code, build artifacts, and sensitive configuration files if the bucket is compromised.",
        "remediation": "Navigate to the CodePipeline settings, edit the pipeline, and in the 'Artifact store' section, configure a KMS key for encryption.",
        "pci_requirement": "PCI DSS 6.2.1",
        "check_function": check_codepipeline_unencrypted_artifacts
    },
    {
        "rule_id": "CODEPIPELINE_002",
        "section": "CI/CD Security",
        "name": "CodePipeline is missing a manual approval stage",
        "severity": SEVERITY["LOW"],
        "description": "A CodePipeline does not have a manual approval stage. This is a security risk, especially for pipelines deploying to production, as it allows code changes to be deployed automatically without human oversight.",
        "remediation": "Edit the pipeline and add a new stage before the production deployment action. In this stage, add a 'Manual approval' action. This will pause the pipeline until an authorized user approves the deployment.",
        "pci_requirement": "PCI DSS 6.5.1",
        "check_function": check_codepipeline_no_manual_approval
    },
    {
        "rule_id": "CODEPIPELINE_003",
        "section": "CI/CD Security",
        "name": "CodePipeline lacks a security scan and has no compensating control",
        "severity": SEVERITY["MEDIUM"],
        "description": "A CodePipeline does not have an integrated security scanning stage, and Amazon Inspector is also not configured to scan container images in this region. This means code or images could be deployed to production with known vulnerabilities without any automated checks.",
        "remediation": "The best practice is to add a security scanning stage to your pipeline (e.g., using CodeBuild with tools like Trivy, SonarQube, or AWS Inspector). As a baseline, ensure Amazon Inspector is enabled for ECR in the region.",
        "pci_requirement": "PCI DSS 6.2.3",
        "data_sources": ['codepipeline', 'inspector', 'ecr'],
        "check_function": check_codepipeline_no_scan_and_no_inspector
    },
    {
        "rule_id": "CODEPIPELINE_004",
        "section": "CI/CD Security",
        "name": "CodePipeline lacks a security scan but Inspector is active",
        "severity": SEVERITY["LOW"],
        "description": "A CodePipeline does not have a specific security scanning stage. However, Amazon Inspector is active for ECR in this region, providing a compensating control for container image vulnerabilities. While this is a good baseline, integrating a scan directly into the pipeline provides earlier feedback.",
        "remediation": "For more robust security, add a dedicated security scanning stage to your pipeline. This allows you to fail the build early if critical vulnerabilities are found, rather than discovering them after the image is in ECR.",
        "pci_requirement": "PCI DSS 6.2.3",
        "data_sources": ['codepipeline', 'inspector', 'ecr'],
        "check_function": check_codepipeline_no_scan_but_inspector_ok
    },
    {
        "rule_id": "WAF_001",
        "section": "Logging & Monitoring",
        "name": "WAF with disabled Sampled Requests",
        "severity": SEVERITY["LOW"],
        "description": "A Web ACL does not have 'Sampled Requests' enabled. While not as critical as full logging, this feature provides free, real-time visibility into the traffic that matches the rules, which is very useful for debugging and operational monitoring.",
        "remediation": "Navigate to the WAF console, select the affected Web ACL, go to the 'Visibility and metrics' tab, and enable the 'Sampled requests' option.",
        "pci_requirement": "PCI DSS 6.4.2",
        "check_function": check_waf_sampled_requests_disabled
    },
    {
        "rule_id": "WAF_002",
        "section": "Logging & Monitoring",
        "name": "WAF Web ACL with Full Logging Disabled",
        "severity": SEVERITY["HIGH"],
        "description": "A Web ACL does not have a logging destination configured. This is a critical security gap as it prevents the collection of detailed traffic logs necessary for incident investigation, forensic analysis, and compliance auditing. Without these logs, it is nearly impossible to analyze an attack or troubleshoot false positives.",
        "remediation": "Navigate to the WAF console, select the affected Web ACL, go to the 'Logging and metrics' tab, and enable logging. You will need to configure an Amazon Kinesis Data Firehose as the destination to store the logs, which can then be sent to S3, CloudWatch, or other analysis tools.",
        "pci_requirement": "PCI DSS 6.4.2",
        "check_function": check_waf_logging_destination_disabled
    },
    {
        "rule_id": "WAF_003",
        "section": "Security Services",
        "name": "AWS WAF Classic (v1) usage detected",
        "severity": SEVERITY["LOW"],
        "description": "Usage of AWS WAF Classic (v1) has been detected. AWS recommends migrating to the latest version, AWS WAF (v2), as it offers a more powerful and flexible rules engine, better provider-managed rule sets, lower latency, more efficient pricing, and better integration with services like API Gateway, Cognito, and AppSync.",
        "remediation": "Plan the migration of your WAF Classic Web ACLs to WAFv2. You can use the migration wizard in the AWS console or AWS Firewall Manager. The general process involves: 1. Creating a new Web ACL in WAFv2. 2. Replicating and improving the existing rules. 3. Testing the new ACL in a non-production environment. 4. Associating the new ACL with your resources (CloudFront, ALB, etc.) and disassociating the old WAF Classic ACL.",
        "pci_requirement": "PCI DSS 6.4.2",
        "check_function": check_waf_classic_in_use
    },
    {
        "rule_id": "COMPUTE_001",
        "section": "Identity & Access",
        "name": "Running EC2 instance has no IAM role associated",
        "severity": SEVERITY["MEDIUM"],
        "description": "An active EC2 instance has been detected without an associated IAM role. This directly implies that it lacks the necessary permissions to interact with other AWS services. For example, it cannot send logs to CloudWatch, which prevents security tools installed on the instance (like a FIM such as OSSEC) from forwarding their critical alerts. This creates a major gap in security visibility and centralized monitoring.",
        "remediation": "Create an IAM role with the minimum necessary permissions for the instance's function (e.g., 'CloudWatchAgentServerPolicy' for logging). Then, navigate to the EC2 console, select the instance, and under 'Actions' -> 'Security' -> 'Modify IAM role', attach the newly created role.",
        "pci_requirement": "PCI DSS 10.2.1",
        "check_function": check_ec2_instance_missing_iam_role
    },
    {
        "rule_id": "LAMBDA_PCI_223B_001",
        "section": "PCI DSS 2.2.3.b",
        "name": "Lambda function without any tags",
        "severity": SEVERITY["MEDIUM"],
        "description": "One or more Lambda functions do not have any tags assigned. Tagging is essential for governance, cost management, and identifying resources. For compliance, it's the first step to classify functions based on their role and the data they handle.",
        "remediation": "Assign meaningful tags to every Lambda function. At a minimum, consider tags such as 'Project', 'Owner', 'Environment', and a data classification tag like 'Sensitivity' (e.g., PCI, High, Medium, Low).",
        "pci_requirement": "PCI DSS 2.2.3.b",
        "check_function": check_lambda_missing_any_tag
    },
    {
        "rule_id": "LAMBDA_PCI_223B_002",
        "section": "PCI DSS 2.2.3.b",
        "name": "Lambda function uses a privileged IAM role",
        "severity": SEVERITY["HIGH"],
        "description": "A Lambda function is using an IAM role that has been identified as privileged (e.g., AdministratorAccess). This grants excessive permissions to the function. If the Lambda code has a vulnerability, it could be exploited by an attacker to gain extensive control over your AWS account.",
        "remediation": "Create a new, dedicated IAM role for the Lambda function following the principle of least privilege. Grant only the specific permissions the function needs to perform its task. Avoid using broad, administrative policies for Lambda execution roles.",
        "pci_requirement": "PCI DSS 2.2.3.b",
        "check_function": check_lambda_using_privileged_role
    },
    {
        "rule_id": "S3_001",
        "section": "Internet Exposure",
        "name": "S3 bucket with public access",
        "severity": SEVERITY["MEDIUM"],
        "description": "An S3 bucket has been detected that allows public access via ACLs or bucket policies. This exposes the bucket contents to the internet, potentially allowing unauthorized users to read, and in some cases modify, the stored data. Public S3 buckets represent a significant security risk as they can lead to data breaches if sensitive information is inadvertently stored without proper access controls.",
        "remediation": "Navigate to the S3 console, select the affected bucket, and review its permissions. Enable 'Block all public access' in the bucket's permissions tab unless public access is absolutely necessary. If public access is required, ensure that only the specific objects that need to be public are accessible, and consider using CloudFront for better control over content distribution.",
        "pci_requirement": "PCI DSS 1.3.1",
        "check_function": check_s3_public_buckets
    },
    {
        "rule_id": "SECRETS_001",
        "section": "Data Protection", 
        "name": "Secret without automatic rotation enabled",
        "severity": SEVERITY["HIGH"],
        "description": "A secret in AWS Secrets Manager does not have automatic rotation enabled. Without rotation, compromised credentials could remain valid indefinitely, increasing security risk. This is especially critical for database credentials and API keys.",
        "remediation": "Navigate to AWS Secrets Manager, select the affected secret, and configure automatic rotation. For database credentials, use AWS managed Lambda functions. For other secrets, create custom rotation functions.",
        "pci_requirement": "PCI DSS 8.6.2",
        "check_function": check_secrets_rotation_disabled
    },
    {
        "rule_id": "SECRETS_002",
        "section": "Data Protection",
        "name": "Secret encrypted with AWS managed KMS key",
        "severity": SEVERITY["MEDIUM"], 
        "description": "A secret is using an AWS managed KMS key instead of a customer managed key (CMK). Customer managed keys provide better control over encryption, key rotation policies, and access logging.",
        "remediation": "Create a customer managed KMS key and update the secret to use it. Navigate to Secrets Manager, edit the secret's encryption configuration, and select your CMK.",
        "pci_requirement": "PCI DSS 8.6.2",
        "check_function": check_secrets_aws_managed_kms
    },
    {
        "rule_id": "SECRETS_003",
        "section": "Identity & Access",
        "name": "Secret with overly permissive resource policy", 
        "severity": SEVERITY["CRITICAL"],
        "description": "A secret has a resource policy that allows public access or uses wildcard principals. This could allow unauthorized access to sensitive credentials from anywhere on the internet.",
        "remediation": "Navigate to Secrets Manager, select the secret, and review its resource policy. Remove any statements with Principal '*' and restrict access to specific IAM roles or users that require it.",
        "pci_requirement": "PCI DSS 8.6.1",
        "check_function": check_secrets_public_resource_policy
    },
    {
        "rule_id": "SECRETS_004",
        "section": "Business Continuity",
        "name": "Critical secret not replicated for disaster recovery",
        "severity": SEVERITY["MEDIUM"],
        "description": "A secret is not replicated to other regions, creating a single point of failure. If the primary region becomes unavailable, applications dependent on this secret could fail.",
        "remediation": "Enable cross-region replication for critical secrets. In Secrets Manager, select the secret and configure replication to at least one other region.",
        "pci_requirement": "PCI DSS 8.6.1",
        "check_function": check_secrets_no_replication
    },
    {
        "rule_id": "SECRETS_005", 
        "section": "Governance",
        "name": "Secret without tags for classification",
        "severity": SEVERITY["LOW"],
        "description": "A secret has no tags assigned. Tags are essential for governance, cost allocation, and security classification of sensitive credentials.",
        "remediation": "Add appropriate tags to classify the secret. Consider tags like Environment, Owner, Sensitivity, and Purpose to improve governance and cost tracking.",
        "pci_requirement": "PCI DSS 8.6.1",
        "check_function": check_secrets_no_tags
    },
    {
        "rule_id": "SECRETS_006",
        "section": "Data Protection", 
        "name": "Secret with excessive rotation interval",
        "severity": SEVERITY["MEDIUM"],
        "description": "A secret has automatic rotation enabled but with an interval exceeding 90 days. Long rotation intervals reduce the effectiveness of credential rotation as a security control.",
        "remediation": "Navigate to Secrets Manager, select the secret, and modify the rotation configuration to use an interval of 90 days or less for enhanced security.",
        "pci_requirement": "PCI DSS 8.6.3",
        "check_function": check_secrets_long_rotation_interval
    },
    {
        "rule_id": "LAMBDA_SEC_001",
        "section": "Credential Management",
        "name": "Lambda function with hardcoded credentials",
        "severity": SEVERITY["CRITICAL"],
        "description": "One or more Lambda functions contain hardcoded credentials, API keys, passwords, or other sensitive information in environment variables. This represents a critical security vulnerability as these credentials are stored in plaintext and can be accessed by anyone with permissions to view the Lambda function configuration. Hardcoded credentials in Lambda functions violate the principle of least privilege and create significant security risks including credential theft, unauthorized access to external services, and potential data breaches.",
        "remediation": "Immediately remove all hardcoded credentials from Lambda environment variables and replace them with secure alternatives: 1) Use AWS Secrets Manager to store sensitive credentials and retrieve them programmatically in your function code. 2) Use AWS Systems Manager Parameter Store for configuration values and secrets. 3) Use IAM roles and policies to grant the Lambda function only the permissions it needs to access other AWS services. 4) For database connections, use IAM database authentication when possible. 5) Implement credential rotation policies and monitor access to sensitive resources. 6) Review your CI/CD pipeline to ensure secrets are not accidentally committed to source code.",
        "pci_requirement": "PCI DSS 8.3.2",
        "check_function": check_lambda_hardcoded_credentials
    }
]
