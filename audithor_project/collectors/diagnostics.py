"""Safe, structured collection diagnostics shared by the audited collectors."""
import json
import logging
import time
import uuid
import boto3
from contextlib import contextmanager
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

AWS_CONFIG = Config(connect_timeout=5, read_timeout=20,
                    retries={"mode": "standard", "total_max_attempts": 3})
AWS_ERRORS = (BotoCoreError, ClientError)
logger = logging.getLogger("audithor.collection")


def _nested_operation_failed(units, service, region, first_unit):
    """A nested failed or skipped unit already represents the operation."""
    return any(u["service"] == service and u["region"] == region and u["status"] in {"failed", "skipped"} and u.get("impact") != "enrichment" for u in units[first_unit:])


def classify_error(exc):
    response = (getattr(exc, "response", None) or {})
    code = response.get("Error", {}).get("Code", type(exc).__name__)
    meta = response.get("ResponseMetadata", {})
    if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ACCESS_DENIED"}:
        category, retryable = "permission_denied", False
    elif code in {"InvalidClientTokenId", "UnrecognizedClientException", "AuthFailure",
                  "ExpiredToken", "ExpiredTokenException", "SignatureDoesNotMatch",
                  "NoCredentialsError", "PartialCredentialsError"}:
        category, retryable = "authentication_error", False
    elif code == "OptInRequired":
        category, retryable = "region_not_enabled", False
    elif code in {"ConnectTimeoutError", "EndpointConnectionError", "ReadTimeoutError",
                  "ConnectionClosedError", "SSLError", "ProxyConnectionError"}:
        category, retryable = "connectivity_error", True
    elif code in {"Throttling", "ThrottlingException", "TooManyRequestsException",
                  "RequestLimitExceeded", "ProvisionedThroughputExceededException"}:
        category, retryable = "throttled", True
    elif code in {"ResourceNotFoundException", "ResourceNotFoundFault", "DBSubnetGroupNotFoundFault"}:
        category, retryable = "resource_disappeared", False
    elif meta.get("HTTPStatusCode", 0) >= 500:
        category, retryable = "aws_service_error", True
    else:
        category, retryable = "aws_error", False
    return {"category": category, "awsCode": code, "retryable": retryable,
            "awsRequestId": meta.get("RequestId"), "awsOperation": getattr(exc, "operation_name", None),
            "httpStatus": meta.get("HTTPStatusCode"),
            "retryAttempts": meta.get("RetryAttempts", 0)}


class Collection:
    def __init__(self, collector, session):
        self.collector = collector
        self.scan_id = getattr(session, "_audithor_scan_id", None) or str(uuid.uuid4())
        self.request_id = getattr(session, "_audithor_request_id", None)
        self.account_id = getattr(session, "_audithor_account_id", None)
        self.units = []
        self.coverage_known = True
        self._regions = None
        self.started = time.monotonic()

    def record(self, service, region, operation, status, **details):
        unit = dict(service=service, region=region, operation=operation,
                    status=status, **details)
        self.units.append(unit)
        category = unit.get("category")
        level = (logging.ERROR if category == "authentication_error"
                 else logging.WARNING if status == "failed" else logging.INFO)
        # Only allowlisted diagnostic fields: never log exception strings or AWS payloads.
        event = dict(event="collection.operation", timestamp=datetime.now(timezone.utc).isoformat(),
                     scanId=self.scan_id, requestId=self.request_id, collector=self.collector, accountId=self.account_id, **unit)
        logger.log(level, json.dumps(event))
        return unit

    def failure(self, exc, service, region, operation, **details):
        return self.record(service, region, operation, "failed",
                           **classify_error(exc), **details)

    @contextmanager
    def operation(self, service, region, operation, **details):
        started = time.monotonic()
        first_unit = len(self.units)
        logger.debug(json.dumps(dict(event="collection.started", scanId=self.scan_id,
                                     service=service, region=region, operation=operation)))
        try:
            yield
        except AWS_ERRORS as exc:
            self.failure(exc, service, region, operation,
                         durationMs=round((time.monotonic()-started)*1000), **details)
        else:
            if _nested_operation_failed(self.units, service, region, first_unit):
                return
            self.record(service, region, operation, "complete",
                        durationMs=round((time.monotonic()-started)*1000), **details)

    def regions(self, session, service):
        partition = session.get_partition_for_region(session.region_name or "us-east-1")
        available = set(session.get_available_regions(service, partition_name=partition))
        if self._regions is None:
            bootstrap = session.region_name or "us-east-1"
            try:
                response = session.client("ec2", region_name=bootstrap, config=AWS_CONFIG).describe_regions(AllRegions=True)
                self._regions = {r["RegionName"]: r["OptInStatus"] for r in response["Regions"]}
                self.record("ec2", bootstrap, "describe_regions", "complete", impact="discovery")
            except AWS_ERRORS as exc:
                self.coverage_known = False
                self._regions = {}
                self.failure(exc, "ec2", bootstrap, "describe_regions", impact="discovery")
        if not available:
            self.coverage_known = False
            self.record(service, None, "service_region_catalog", "failed", category="empty_sdk_catalog")
        result = []
        for region in sorted(available | set(self._regions)):
            opt_in = self._regions.get(region)
            if opt_in == "not-opted-in":
                self.record(service, region, "region_selection", "skipped", category="region_not_enabled")
            elif region not in available:
                self.record(service, region, "region_selection", "skipped", category="service_not_available")
            else:
                result.append(region)
        return result

    def finish(self, results):
        failures = [u for u in self.units if u["status"] == "failed"]
        completed = [u for u in self.units if u["status"] == "complete" and u.get("impact") not in {"discovery", "enrichment"}]
        has_data = any(isinstance(v, list) and v for v in results.values())
        if failures:
            status = "partial" if completed or has_data else "failed"
        elif completed:
            status = "complete"
        elif self.units:
            status = "not_applicable"
        else:
            status = "unknown"
            self.coverage_known = False
        results["_collection"] = {"schemaVersion": 2, "scanId": self.scan_id, "requestId": self.request_id,
                                  "status": status, "coverageKnown": self.coverage_known, "sdkVersion": boto3.__version__,
                                  "units": self.units}
        logger.info(json.dumps(dict(event="collection.finished", scanId=self.scan_id,
                                    collector=self.collector, status=status,
                                    failedOperations=len(failures), completedOperations=len(completed),
                                    durationMs=round((time.monotonic()-self.started)*1000))))
        return results
