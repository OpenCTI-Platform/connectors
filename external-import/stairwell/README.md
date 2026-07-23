# OpenCTI Stairwell Connector (External Import)

External-import connector that periodically pulls high-confidence Stairwell
indicators (hashes, domains, IPs, URLs) and ingests them into OpenCTI as
Indicators with related observables, wrapped in a Grouping or Report.

## Requirements

- OpenCTI Platform >= 6.8.12
- A Stairwell API token (Bearer auth)

## Configuration

Configuration is loaded via the `connectors-sdk` settings layer: from
`src/config.yml` if present, otherwise from environment variables.
Environment variables override the file.

### OpenCTI

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | yes | — | OpenCTI platform URL |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | yes | — | OpenCTI admin token |

### Connector

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | yes | — | UUIDv4 unique to this instance |
| Connector type | `connector.type` | `CONNECTOR_TYPE` | yes | `EXTERNAL_IMPORT` | Must be `EXTERNAL_IMPORT` |
| Connector name | `connector.name` | `CONNECTOR_NAME` | yes | `Stairwell Import` | Display name in OpenCTI |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | yes | `stairwell` | Free-form import scope tag |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | no | `error` | `debug`, `info`, `warn`, `error` |
| Duration period | `connector.duration_period` | `CONNECTOR_DURATION_PERIOD` | no | `P1D` | ISO 8601 interval between runs (scheduling) |

### Stairwell

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| API token | `stairwell.api_token` | `STAIRWELL_API_TOKEN` | yes | — | Stairwell API token |
| API base URL | `stairwell.api_base_url` | `STAIRWELL_API_BASE_URL` | no | `https://app.stairwell.com` | Override for staging |
| Organization ID | `stairwell.organization_id` | `STAIRWELL_ORGANIZATION_ID` | no | — | Adds rate-limit header |
| User ID | `stairwell.user_id` | `STAIRWELL_USER_ID` | no | — | Adds rate-limit header |
| Import TLP | `stairwell.import_tlp` | `STAIRWELL_IMPORT_TLP` | no | `green` | `clear`, `green`, `amber`, `amber+strict`, `red` |
| First-run window | `stairwell.import_first_run_window` | `STAIRWELL_IMPORT_FIRST_RUN_WINDOW` | no | `P1D` | ISO 8601 duration to backfill on first run |
| Max indicators | `stairwell.import_max_indicators` | `STAIRWELL_IMPORT_MAX_INDICATORS` | no | `1000` | Cap per run |
| Page size | `stairwell.import_page_size` | `STAIRWELL_IMPORT_PAGE_SIZE` | no | `100` | API page size |
| Indicator validity | `stairwell.import_indicator_validity_days` | `STAIRWELL_IMPORT_INDICATOR_VALIDITY_DAYS` | no | `90` | `valid_until` offset |
| Min bucket | `stairwell.import_min_bucket` | `STAIRWELL_IMPORT_MIN_BUCKET` | no | `HIGH` | `LOW`, `MEDIUM`, `HIGH`, `MALICIOUS` |
| Import scope | `stairwell.import_scope` | `STAIRWELL_IMPORT_SCOPE` | no | `environment` | `environment` (your tenant) or `global` |
| Wrapper | `stairwell.import_wrapper` | `STAIRWELL_IMPORT_WRAPPER` | no | `grouping` | `grouping` or `report` |

## Behavior

- **Periodic poll.** Scheduling is owned by the OpenCTI connector helper
  (`schedule_process`) on the `CONNECTOR_DURATION_PERIOD` interval; each run
  opens a work item so it appears in the OpenCTI work log. The first-run
  backfill window prevents re-importing the full history.
- **CEL filtering.** Min-bucket and time cutoff are pushed to Stairwell as a
  CEL expression so the API only returns relevant rows.
- **Per-run wrapper.** All ingested objects are grouped under a single
  Grouping (default) or Report SDO so reviewers can see exactly what landed in
  one batch.
- **Indicator validity.** Each Indicator gets `valid_from` = ingest time,
  `valid_until` = `valid_from + import_indicator_validity_days`.

## Installation

### Via Docker

```bash
docker build -t opencti/connector-stairwell-import:latest .
```

Then add the service from `docker-compose.yml` to your OpenCTI deployment.

### Local development

```bash
cd src
pip install -r requirements.txt
cp config.yml.sample config.yml   # edit values
python3 main.py
```

## Tests

```bash
cd src
pip install -r requirements.txt -r tests/test-requirements.txt
PYTHONPATH=. pytest tests/
```
