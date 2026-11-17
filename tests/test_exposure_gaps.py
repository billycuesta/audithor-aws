from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from audithor.collectors import exposure


class Session:
    region_name = "us-east-1"

    def __init__(self, clients):
        self.clients = clients

    def get_partition_for_region(self, region):
        return "aws"

    def get_available_regions(self, service, **kwargs):
        return ["us-east-1"]

    def client(self, service, **kwargs):
        return self.clients.get(service, Mock())


def prepare(monkeypatch, regions=("us-east-1",)):
    monkeypatch.setattr(exposure, "collect_network_ports_data", lambda *_: [])
    monkeypatch.setattr(exposure, "get_all_aws_regions", lambda *_: list(regions))
    monkeypatch.setattr(exposure, "EXPOSURE_SERVICES", {})


def test_collect_exposure_keeps_existing_shape_and_adds_cloudfront_and_domains(monkeypatch):
    cf = Mock()
    cf.get_paginator.return_value.paginate.return_value = [{"DistributionList": {"Items": [{
        "Id": "D1", "DomainName": "d.example", "Aliases": {"Items": ["www.example"]}, "Enabled": True,
        "Origins": {"Items": [{"Id": "origin", "DomainName": "bucket.s3.amazonaws.com", "S3OriginConfig": {"OriginAccessIdentity": "identity"}}]},
        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"}, "CacheBehaviors": {"Items": [{"PathPattern": "/api/*", "ViewerProtocolPolicy": "https-only"}]},
        "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"}, "WebACLId": ""
    }]}}]
    v1 = Mock()
    v1.get_paginator.return_value.paginate.return_value = [{"items": [{"domainName": "api.example", "securityPolicy": "TLS_1_2", "endpointConfiguration": {"types": ["REGIONAL"]}}]}]
    v1.get_base_path_mappings.return_value = {"items": [{"basePath": "v1", "restApiId": "abc", "stage": "prod"}]}
    v2 = Mock()
    v2.get_paginator.return_value.paginate.return_value = [{"Items": [{"DomainName": "http.example", "SecurityPolicy": "TLS_1_2", "DomainNameConfigurations": [{"EndpointType": "REGIONAL"}]}]}]
    v2.get_api_mappings.return_value = {"Items": [{"ApiId": "api-id", "Stage": "prod", "ApiMappingKey": "v2"}]}
    prepare(monkeypatch)
    result = exposure.collect_exposure_data(Session({"cloudfront": cf, "apigateway": v1, "apigatewayv2": v2}))
    assert set(result) == {"summary", "details", "network_ports", "Enrichment"}
    distribution = result["details"]["CloudFront Distributions"]["Global"][0]
    assert distribution["Id"] == "D1"
    assert distribution["DomainName"] == "d.example"
    assert distribution["Enabled"] is True
    assert distribution["Origins"][0]["DomainName"] == "bucket.s3.amazonaws.com"
    assert distribution["Origins"][0]["OriginAccessControlPresent"] is False
    assert distribution["Aliases"] == ["www.example"]
    assert distribution["Origins"][0]["OriginType"] == "S3"
    assert distribution["Origins"][0]["OriginAccessIdentityPresent"] is True
    assert distribution["DefaultCacheBehaviorViewerProtocolPolicy"] == "allow-all"
    assert distribution["CacheBehaviors"][0] == {"PathPattern": "/api/*", "ViewerProtocolPolicy": "https-only"}
    assert distribution["ViewerCertificateMinimumProtocolVersion"] == "TLSv1.2_2021"
    assert distribution["WebACLId"] == ""
    assert distribution["Enrichment"]["cloudFront"]["status"] == "complete"
    domains = result["details"]["API Custom Domains"]
    assert domains["us-east-1"][0]["DomainName"] == "api.example"
    assert domains["us-east-1"][0]["SecurityPolicy"] == "TLS_1_2"
    assert domains["us-east-1"][0]["EndpointType"] == "REGIONAL"
    assert domains["us-east-1"][0]["Mappings"][0] == {"BasePath": "v1", "RestApiId": "abc", "Stage": "prod"}
    assert domains["us-east-1"][1]["DomainName"] == "http.example"
    assert domains["us-east-1"][1]["SecurityPolicy"] == "TLS_1_2"
    assert domains["us-east-1"][1]["Certificate"] is None
    assert domains["us-east-1"][1]["EndpointType"] == "REGIONAL"
    assert domains["us-east-1"][1]["Mappings"][0] == {"ApiId": "api-id", "Stage": "prod", "ApiMappingKey": "v2"}
    assert result["Enrichment"]["cloudFront"] == {"status": "complete"}
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v1"]["status"] == "complete"
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v2"]["status"] == "complete"


def test_access_denied_does_not_create_cloudfront_or_api_placeholders(monkeypatch):
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "List")
    cf = Mock()
    cf.get_paginator.side_effect = denied
    v1 = Mock()
    v1.get_paginator.side_effect = denied
    v2 = Mock()
    v2.get_paginator.return_value.paginate.return_value = []
    prepare(monkeypatch)
    result = exposure.collect_exposure_data(Session({"cloudfront": cf, "apigateway": v1, "apigatewayv2": v2}))
    assert "CloudFront Distributions" not in result["details"]
    assert "API Custom Domains" not in result["details"]
    assert result["Enrichment"]["cloudFront"] == {"status": "failed", "reason": "permission_denied"}
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v1"] == {"status": "failed", "reason": "permission_denied"}
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v2"]["status"] == "complete"


def test_api_v2_failure_keeps_v1_records_and_marks_only_v2_failed(monkeypatch):
    v1 = Mock()
    v1.get_paginator.return_value.paginate.return_value = [{"items": [{"domainName": "api.example"}]}]
    v1.get_base_path_mappings.return_value = {"items": [{"basePath": "v1", "restApiId": "abc", "stage": "prod"}]}
    v2 = Mock()
    v2.get_paginator.side_effect = ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetDomainNames")
    cf = Mock()
    cf.get_paginator.return_value.paginate.return_value = []
    prepare(monkeypatch)
    result = exposure.collect_exposure_data(Session({"cloudfront": cf, "apigateway": v1, "apigatewayv2": v2}))
    assert result["details"]["API Custom Domains"]["us-east-1"][0]["DomainName"] == "api.example"
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v1"]["status"] == "complete"
    assert result["Enrichment"]["apiDomains"]["regions"]["us-east-1"]["v2"] == {"status": "failed", "reason": "permission_denied"}


def test_new_calls_use_real_botocore_models_through_collector(monkeypatch):
    cf = boto3.client("cloudfront", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    v1 = boto3.client("apigateway", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    v2 = boto3.client("apigatewayv2", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(cf) as cf_stub, Stubber(v1) as v1_stub, Stubber(v2) as v2_stub:
        cf_stub.add_response("list_distributions", {"DistributionList": {"Items": [{
            "Id": "D1", "ARN": "arn:aws:cloudfront::123456789012:distribution/D1", "Status": "Deployed", "LastModifiedTime": "2024-01-01T00:00:00Z", "DomainName": "d.example", "Aliases": {"Quantity": 0}, "Origins": {"Quantity": 1, "Items": [{"Id": "origin", "DomainName": "origin.example", "S3OriginConfig": {"OriginAccessIdentity": ""}}]}, "DefaultCacheBehavior": {"TargetOriginId": "x", "ViewerProtocolPolicy": "https-only", "TrustedSigners": {"Enabled": False, "Quantity": 0}, "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}, "Headers": {"Quantity": 0}, "QueryStringCacheKeys": {"Quantity": 0}}, "MinTTL": 0}, "CacheBehaviors": {"Quantity": 0}, "CustomErrorResponses": {"Quantity": 0}, "Comment": "", "PriceClass": "PriceClass_100", "Enabled": True, "Staging": False, "ViewerCertificate": {"CloudFrontDefaultCertificate": True}, "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}}, "WebACLId": "", "HttpVersion": "http2", "IsIPV6Enabled": True}], "IsTruncated": False, "Marker": "", "MaxItems": 100, "Quantity": 1}})
        v1_stub.add_response("get_domain_names", {"items": [{"domainName": "rest.example", "securityPolicy": "TLS_1_2", "endpointConfiguration": {"types": ["REGIONAL"]}}]})
        v1_stub.add_response("get_base_path_mappings", {"items": [{"basePath": "v1", "restApiId": "rest-id", "stage": "prod"}]}, {"domainName": "rest.example"})
        v2_stub.add_response("get_domain_names", {"Items": [{"DomainName": "http.example", "DomainNameConfigurations": [{"EndpointType": "REGIONAL", "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012", "SecurityPolicy": "TLS_1_2"}]}]})
        v2_stub.add_response("get_api_mappings", {"Items": [{"ApiId": "api-id", "Stage": "prod", "ApiMappingKey": "v2"}]}, {"DomainName": "http.example"})
        prepare(monkeypatch)
        result = exposure.collect_exposure_data(Session({"cloudfront": cf, "apigateway": v1, "apigatewayv2": v2}))
        cf_stub.assert_no_pending_responses()
        v1_stub.assert_no_pending_responses()
        v2_stub.assert_no_pending_responses()
    assert result["details"]["CloudFront Distributions"]["Global"][0]["Id"] == "D1"
    assert result["details"]["API Custom Domains"]["us-east-1"][0]["Mappings"][0]["RestApiId"] == "rest-id"
    assert result["details"]["API Custom Domains"]["us-east-1"][1]["Mappings"][0]["ApiId"] == "api-id"
