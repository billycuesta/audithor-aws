# collectors/codepipeline.py
import json
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

def collect_codepipeline_data(session):
    all_pipelines = []
    
    try:
        regions_to_scan = session.get_available_regions("codepipeline")
    except ClientError:
        regions_to_scan = get_all_aws_regions(session)

    for region in regions_to_scan:
        try:
            print(f"Checking CodePipeline in region: {region}")
            codepipeline_client = session.client("codepipeline", region_name=region)
            
            paginator = codepipeline_client.get_paginator("list_pipelines")
            for page in paginator.paginate():
                for pipeline in page.get("pipelines", []):
                    pipeline_name = pipeline.get("name")
                    print(f"Found pipeline: {pipeline_name} in region: {region}")
                    
                    try:
                        # Obtener los detalles del pipeline
                        details = codepipeline_client.get_pipeline(name=pipeline_name)["pipeline"]
                        
                        has_manual_approval = False
                        has_security_scan = False
                        
                        for stage in details.get("stages", []):
                            for action in stage.get("actions", []):
                                if action.get("actionTypeId", {}).get("provider") == "Manual":
                                    has_manual_approval = True
                                
                                provider = action.get("actionTypeId", {}).get("provider")
                                if provider in ["Inspector", "CodeBuild"]:
                                    action_name = action.get("actionName", "").lower()
                                    if "security" in action_name or "scan" in action_name:
                                        has_security_scan = True
                        
                        source_provider = "N/A"
                        source_provider_details = {}
                        if details.get("stages"):
                            source_stage = details["stages"][0]
                            if source_stage.get("actions"):
                                source_action = source_stage["actions"][0]
                                source_provider = source_action.get("actionTypeId", {}).get("provider")
                                source_provider_details = source_action.get("configuration", {})
                        
                        artifact_store = details.get("artifactStore", {})
                        encryption_key = artifact_store.get("encryptionKey", {})
                        is_encrypted = encryption_key.get("id") is not None
                        
                        role_arn = details.get("roleArn", "N/A")
                        
                        pipeline_data = {
                            "Region": region,
                            "Name": pipeline_name,
                            "Created": pipeline.get("created"),
                            "Updated": pipeline.get("updated"),
                            "RoleArn": role_arn,
                            "IsEncrypted": is_encrypted,
                            "HasManualApproval": has_manual_approval,
                            "HasSecurityScan": has_security_scan,
                            "SourceProvider": source_provider,
                            "SourceDetails": source_provider_details,
                            "ARN": pipeline.get("pipelineArn")
                        }
                        
                        all_pipelines.append(pipeline_data)
                        print(f"Successfully processed pipeline: {pipeline_name}")
                        
                    except ClientError as e:
                        print(f"Error getting pipeline '{pipeline_name}' in region {region}: {e}")
                        # Agregar pipeline básico sin detalles en caso de error de permisos
                        basic_pipeline_data = {
                            "Region": region,
                            "Name": pipeline_name,
                            "Created": pipeline.get("created"),
                            "Updated": pipeline.get("updated"),
                            "RoleArn": "Access Denied",
                            "IsEncrypted": False,
                            "HasManualApproval": False,
                            "HasSecurityScan": False,
                            "SourceProvider": "Unknown",
                            "SourceDetails": {},
                            "ARN": pipeline.get("pipelineArn", "N/A"),
                            "Error": str(e)
                        }
                        all_pipelines.append(basic_pipeline_data)
                        continue
                    except Exception as e:
                        print(f"Unexpected error processing pipeline '{pipeline_name}' in region {region}: {e}")
                        continue
                    
        except ClientError as e:
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] not in common_errors:
                print(f"Error processing CodePipeline in region {region}: {e}")
            continue
        except Exception as e:
            print(f"Unexpected error in region {region}: {e}")
            continue
    
    print(f"Total pipelines found: {len(all_pipelines)}")
    return {"pipelines": all_pipelines}