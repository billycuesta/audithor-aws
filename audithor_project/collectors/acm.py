"""ACM inventory with explicit regional and resource coverage."""
from .diagnostics import Collection, AWS_CONFIG, AWS_ERRORS, classify_error


def _iso_dates(record):
    for key in ("IssuedAt", "NotAfter"):
        if key in record and hasattr(record[key], "isoformat"):
            record[key] = record[key].isoformat()
    return record


def collect_acm_data_web(session):
    diagnostics = Collection("acm", session)
    certificates = []
    for region in diagnostics.regions(session, "acm"):
        with diagnostics.operation("acm", region, "list_certificates"):
            client = session.client("acm", region_name=region, config=AWS_CONFIG)
            stop_details = False
            for page in client.get_paginator("list_certificates").paginate():
                summaries = page.get("CertificateSummaryList", [])
                for index, summary in enumerate(summaries):
                    arn = summary["CertificateArn"]
                    try:
                        certificate = client.describe_certificate(CertificateArn=arn)["Certificate"]
                    except AWS_ERRORS as exc:
                        diagnostics.failure(exc, "acm", region, "describe_certificate", resourceId=arn)
                        # Preserve the enumerated resource when its details could not be read.
                        certificates.append(_iso_dates(dict(summary, Region=region, DetailsStatus="unknown")))
                        if classify_error(exc)["category"] == "connectivity_error":
                            for remaining in summaries[index + 1:]:
                                certificates.append(_iso_dates(dict(remaining, Region=region, DetailsStatus="unknown")))
                            stop_details = True
                            break
                        continue
                    certificate["Region"] = region
                    certificate["DetailsStatus"] = "complete"
                    certificates.append(_iso_dates(certificate))
                if stop_details:
                    break
    certificates.sort(key=lambda c: (c.get("Region", ""), c.get("DomainName", "")))
    return diagnostics.finish({"certificates": certificates})
