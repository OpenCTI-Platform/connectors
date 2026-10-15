# OpenCTI Stairwell Connector (External Import)

External-import connector that periodically pulls MalEval-malicious files
from Stairwell and ingests them into OpenCTI as file hash Indicators. The
IPs, domains, and URLs Stairwell extracted from each file come in as related
observables, not Indicators. Everything is wrapped in a Grouping or Report.

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
| Import TLP | `stairwell.import_tlp` | `STAIRWELL_IMPORT_TLP` | no | `green` | `clear`, `white`, `green`, `amber`, `amber+strict`, `red` |
| First-run window | `stairwell.import_first_run_window` | `STAIRWELL_IMPORT_FIRST_RUN_WINDOW` | no | `P1D` | ISO 8601 duration to backfill on first run |
| Max indicators | `stairwell.import_max_indicators` | `STAIRWELL_IMPORT_MAX_INDICATORS` | no | `1000` | Soft cap per run, checked between pages (a run can overshoot by less than one page); the rest of the window is imported by later runs |
| Page size | `stairwell.import_page_size` | `STAIRWELL_IMPORT_PAGE_SIZE` | no | `100` | API page size |
| Indicator validity | `stairwell.import_indicator_validity_days` | `STAIRWELL_IMPORT_INDICATOR_VALIDITY_DAYS` | no | `90` | `valid_until` offset |
| Min bucket | `stairwell.import_min_bucket` | `STAIRWELL_IMPORT_MIN_BUCKET` | no | `HIGH` | `LOW`, `MEDIUM`, `HIGH`, `VERY_HIGH` |
| Import scope | `stairwell.import_scope` | `STAIRWELL_IMPORT_SCOPE` | no | `environment` | Reserved for forward-compat — accepted but **not yet effective**; every run currently queries the full corpus |
| Wrapper | `stairwell.import_wrapper` | `STAIRWELL_IMPORT_WRAPPER` | no | `grouping` | `grouping` or `report` |

## Behavior

- **Periodic poll.** Built on `connectors_sdk.ExternalImportConnector` with
  one data processor (`MalEvalFilesProcessor`): the SDK runs it every
  `CONNECTOR_DURATION_PERIOD`, opens a work item per run, sends the bundle,
  and saves state only after a successful run. The first-run backfill window
  prevents re-importing the full history.
- **Filtering.** A CEL expression pushes the malicious flag and the time cutoff
  to Stairwell server-side. The minimum-bucket threshold is applied client-side
  after each page is fetched, because the API rejects `in`-operator bucket
  queries (returns HTTP 500).
- **Lossless watermark.** State (`ConnectorState`) holds the committed
  `watermark` and, while a window is being drained, a pending cursor
  (`pending_cutoff`, `pending_window_end`, `pending_page_token`). A run that
  hits the cap saves the cursor and the next run resumes from it; the
  watermark advances only after the window's last page is sent. A failed page
  fetch or bundle send fails the run and no state is saved, so the next run
  retries the same window. If Stairwell rejects a saved page token (4xx other
  than 429), the run restarts the window from its first page. Re-sent objects
  are deduplicated by their IDs, which are OpenCTI's canonical ones (pycti's
  `generate_id()` for SDOs and relationships, spec-standard IDs for
  observables), so the same entity from another connector merges with ours.
  Each bundle carries the Stairwell author identity and the TLP marking
  definition it references.
  State saved by versions of this connector that predate the SDK (`last_run`
  plus a nested `pending` cursor) is adopted on the first run, so an
  in-progress backlog resumes instead of restarting.
- **Network values are observables, not Indicators.** Each IP, domain, and
  URL Stairwell extracted from a file becomes an observable linked to that
  file by a `related-to` relationship, with a link to the Stairwell search.
  Values extracted from malware include benign infrastructure (OS update
  hosts, public DNS resolvers, XML namespaces), so promoting them to
  Indicators would put them on blocklists fed from OpenCTI.
- **Input validation.** An object whose SHA-256 is not 64 hex characters is
  skipped (logged), since an invalid Indicator pattern would make OpenCTI
  reject the whole run's bundle; malformed SHA-1/MD5 values are left off the
  file, extracted IPs that are not valid addresses are dropped, and source
  timestamps are normalised to UTC. Objects without a MalEval bucket at or
  above `import_min_bucket` are filtered.
- **Per-run wrapper.** Each run's objects are grouped under their own
  Grouping (default) or Report SDO, so reviewers can see exactly what landed
  in one batch; `import_wrapper` accepts only `grouping` or `report`.
- **Indicator validity.** Each Indicator's `valid_from` is derived from the
  Stairwell first-seen time (falling back to the run start time), and
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
# From the connector directory:
pip install -r tests/test-requirements.txt
pytest tests/
```
