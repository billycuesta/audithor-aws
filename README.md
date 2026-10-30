# AudiThor-AWS

```text
  █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗ ██████╗ ██████╗
 ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
 ███████║██║   ██║██║  ██║██║   ██║   ███████║██║   ██║██████╔╝
 ██╔══██║██║   ██║██║  ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗
 ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

AWS Security Audit powered by automation to detect risk faster and prioritize remediation.

AudiThor is a local web app for read-only AWS security audits. It provides a single workspace to scan accounts, import/export evidence, review findings by service, and document scope and auditor notes during an assessment.

## Who this is for

- Audit teams running PCI DSS, SOC 2, ISO 27001, SWIFT, or internal security assessments.
- Cloud security teams that need fast evidence collection across multiple AWS services.
- Consultants that need repeatable audits with JSON-based portability.

## Key features

### Startup and workflow
- Landing page as first screen with AudiThor logo and credentials form.
- Scan-gated app flow: views are available after scan/import is completed.
- Import JSON directly from landing page (no need to rescan).

### Audit coverage
- IAM, Access Analyzer, Federation/Identity Center.
- Internet Exposure, Network Policies, Connectivity.
- GuardDuty, WAF, CloudTrail, CloudWatch.
- Inspector, ACM, Compute, Databases, ECR, CodePipeline.
- Config + Security Hub deep-dive and status checks.
- Inventory summary module.

### Playground
The Playground offers path analysis and permission simulation.

### Auditor productivity
- In-scope tagging with mandatory reason.
- Auditor Notes view with:
  - Scoped resources and saved reasons.
  - Manual notes creation/editing.
  - Unified evidence context via JSON import/export.

## Tech stack

- Backend: Python 3, Flask, Boto3 (`audithor/audithor_app.py`)
- Frontend: HTML, Tailwind CSS, Chart.js, vanilla JS modules

## Prerequisites

1. Python 3.8+ and `pip`.

## Installation

```bash
git clone https://github.com/billycuesta/AudiThor-AWS.git
cd AudiThor-AWS/AudiThor-local

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Usage

Run the app:

```bash
python -m audithor
```

Then in the browser:

1. Use **Scan Account** with AWS credentials, or
2. Use **Import JSON** from the landing page.

After scan/import, review modules and use **Auditor Notes** to track scoped assets and notes.

## Credential handling

The browser sends AWS credentials in JSON request bodies to the local Flask process over plain HTTP; the app binds to 127.0.0.1 by default. Credentials are used to create a Boto3 session and are not intentionally persisted or included in structured collection logs or ordinary API responses. Use a trusted workstation; plain HTTP does not protect traffic from other local processes.

Best practices:
- Prefer temporary credentials.
- Use least-privilege read-only policies (`SecurityAudit` + `ViewOnlyAccess` baseline).
- Run in a trusted workstation environment.

## Security

### Network exposure
- The default bind address is `127.0.0.1` and the default port is `5001`. Override them with `AUDITHOR_HOST` and `AUDITHOR_PORT`.
- The API has no authentication. Do not expose it beyond loopback. Other processes on the same machine can reach it; there is no per-launch API token.
- Host and Origin allowlists are checked to mitigate DNS rebinding and cross-site requests. CORS permits loopback origins on the configured port.
- If `AUDITHOR_HOST` is non-loopback, the Host check accepts that exact host and port (along with the two loopback hostnames). Use the exact address clients will enter; never use `0.0.0.0`.
- API and `/run_` POST requests require `application/json`. Request bodies are limited to 64 MiB.

### Errors, logs, and browser protections
- API error responses use generic messages and a category. Structured server logs record diagnostic categories and exception types (and selected request identifiers), not exception text.
- `build_csp` in `audithor/audithor_app.py` sets the dashboard Content-Security-Policy: `default-src 'self'`; scripts may load from self and jsDelivr; styles from self, inline styles and Google Fonts; fonts from self, Google Fonts and data URLs; images from self and data URLs; connections to self and the loopback hosts on the configured port. Objects, base URLs, form submissions and framing are denied.
- Responses set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`; API responses also set `Cache-Control: no-store`. HTML responses also set Permissions-Policy and same-origin Cross-Origin-Opener-Policy.
- Chart.js and the stacked100 plugin CDN scripts use Subresource Integrity. Tailwind is vendored under `audithor/static/vendor` because `cdn.tailwindcss.com` sends no CORS headers, preventing integrity checks. Google Fonts is loaded without integrity because its CSS varies by browser.

### Rendering safety for contributors
Treat AWS data and imported JSON as untrusted. Build markup with the `html` tagged template and `setHtml` from `audithor/static/js/safe_html.js`; use `act()` rather than inline event handlers. Never assign `innerHTML` directly in application code or pass data to `raw()`. The repository currently has no `tests/no_raw_innerhtml.test.mjs` guard test; `setHtml` is the controlled sink and requires a `SafeHtml` value.

### Known limits
- There is no per-launch API token, and the local API uses plain HTTP.
- CI tests with Python 3.12; automated tests do not exercise live AWS integration.

## License

MIT. See `LICENSE`.

### Collection coverage and troubleshooting

ACM, Inspector and Databases responses include `results._collection` coverage metadata. The
change is not additive for every existing field: on these migrated endpoints, `metadata.executionDate`
is ISO 8601 with an offset (previously `YYYY-MM-DD HH:MM:SS TZ`), and `metadata` also includes
`schemaVersion`, `scanId` and `requestId`. Inspector `scan_status` now lists every planned region,
including `DISABLED` regions; previously it listed only `ENABLED` or `ENABLING` regions. Older
exports without `_collection` remain supported and show coverage as unknown. Other collectors have
not yet migrated.

- `complete`: the planned applicable operations completed, including empty inventories.
- `partial`: some data/operations succeeded but a query or enrichment failed.
- `failed`: no primary inventory query completed and no inventory was recovered.
- `not_applicable`: targets were skipped for confirmed region/service reasons.
- `unknown`: no reliable collection plan could be established.
- Inspector `findingsStatus: not_run` means the fast scan did not search findings.
- When ACM or DynamoDB resource details cannot be read, the record carries `DetailsStatus: "unknown"`.
  Database rows can also carry `NetworkDetailsStatus: "unknown"`, `SubnetIds: null` and `Encrypted: null`.

`coverageKnown: false` always prevents a complete assessment in the UI, even when
fallback queries returned data. Regional planning uses account opt-in state plus the
SDK service/partition catalog (its version is included in diagnostics). Discovery
requires `ec2:DescribeRegions`; when denied, catalog regions are attempted and the
coverage limitation remains visible. No credentials or AWS response bodies are logged.

Collection logs are JSON, correlated by `scanId`, per-request `requestId` and AWS request ID where
available. INFO records outcomes and justified omissions; WARNING records incomplete collection;
ERROR records authentication and unexpected failures. The collection logger is configured at INFO;
operation-start DEBUG records are therefore not emitted. SDK calls use 5s connect / 20s read timeouts
and standard retry mode with at most three total attempts per request. These are per-call limits, not
an overall scan deadline.

For `describe_certificate` (ACM) and `describe_table` (DynamoDB), a connectivity error stops further
detail calls and pagination for that operation. Already enumerated resources are retained as unknown
rows and the collection result is partial. Other errors mark only the affected resource unknown.
Database inventory operations are isolated by service and operation. KMS aliases, subnet details and
Inspector EC2 names are optional enrichments: their failure is reported without dropping the main
inventory. An unknown encryption value is shown as UNKNOWN, not NO. DocumentDB subnet details use its
own client.

`POST /run_executive_summary` rules that declare `data_sources` for ACM, Inspector or Databases
consider collection coverage. If a source has `_collection.status` of `partial`, `failed` or `unknown`,
or `coverageKnown` is false or missing, a rule with no violations is returned with status
`NOT ASSESSED`; a rule with violations remains `🚩 RED FLAG`. Either entry includes a `coverage` object
with `service`, `status`, `coverageKnown` and `failedUnits` (at most 10). Older exports without
`_collection` behave as before. The response remains a JSON list; consumers counting findings should
filter on `status`. The affected rule IDs are `INSPECTOR_001`–`INSPECTOR_005`, `DB_001`–`DB_005`,
`ACM_001`, `ECR_004`, `ECR_005`, `CODEPIPELINE_003` and `CODEPIPELINE_004`.

Run regression checks without AWS credentials:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
npm ci --ignore-scripts
npm test
```

The tests include a real botocore Stubber, simulated transport failures, partial
pagination, opt-in filtering, HTTP-200 Inspector account errors, cross-service
isolation, safe diagnostic rendering, complete-view DOM smoke checks and Flask API responses. Live AWS integration
is intentionally separate and has not been run by these tests.
