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

### Auditor productivity
- In-scope tagging with mandatory reason.
- Auditor Notes view with:
  - Scoped resources and saved reasons.
  - Manual notes creation/editing.
  - Unified evidence context via JSON import/export.

## Tech stack

- Backend: Python 3, Flask, Boto3 (`audithor_project/audithor_app.py`)
- Frontend: HTML, Tailwind CSS, Chart.js, vanilla JS modules

## Prerequisites

1. Python 3.8+ and `pip`.
2. `sslscan` (for Playground SSL checks).
   - macOS (Homebrew): `brew install sslscan`
   - Debian/Ubuntu: `sudo apt-get install sslscan`

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
python audithor_project/audithor_app.py
```

Then in the browser:

1. Use **Scan Account** with AWS credentials, or
2. Use **Import JSON** from the landing page.

After scan/import, review modules and use **Auditor Notes** to track scoped assets and notes.

## Credential handling

AudiThor runs locally. Credentials are sent only to your local Flask server.

Best practices:
- Prefer temporary credentials.
- Use least-privilege read-only policies (`SecurityAudit` + `ViewOnlyAccess` baseline).
- Run in a trusted workstation environment.

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
