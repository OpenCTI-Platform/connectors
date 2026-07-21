# OpenCTI External Ingestion Connector Recorded Future ASI

Import [Recorded Future Attack Surface Intelligence (ASI)](https://www.recordedfuture.com/platform/attack-surface-intelligence) exposure findings into OpenCTI as STIX 2.1 incidents, observables, vulnerabilities, and relationships.

Table of Contents

- [OpenCTI External Ingestion Connector Recorded Future ASI](#opencti-external-ingestion-connector-recorded-future-asi)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

Recorded Future Attack Surface Intelligence (ASI) continuously discovers and prioritizes exposure risks across an organization's internet-facing assets. The platform identifies misconfigurations, vulnerable services, and other attack-surface findings with severity scoring, CVE linkage, and remediation guidance.

This connector imports ASI exposure data from a configured project via the ASI API. Findings are converted to STIX 2.1 and sent to OpenCTI as incidents with linked observables (IPv4/IPv6 addresses, domain names), vulnerabilities (CVEs), and relationships.


## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- An active Recorded Future ASI subscription with API access
- An ASI API key and the project ID of the attack-surface project to import

To obtain API credentials or a subscription, see [Recorded Future — Get Started](https://www.recordedfuture.com/get-started).
## Configuration variables

Configuration is set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). See `config.yml.sample` for an annotated example.

### OpenCTI environment variables


| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |


### Base connector environment variables


| Parameter       | config.yml      | Docker environment variable | Default                                                  | Mandatory | Description                                                                                      |
| --------------- | --------------- | --------------------------- | -------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------ |
| Connector ID    | id              | `CONNECTOR_ID`              | —                                                        | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Connector Type  | type            | `CONNECTOR_TYPE`            | `EXTERNAL_IMPORT`                                        | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                    |
| Connector Name  | name            | `CONNECTOR_NAME`            | `Recorded Future ASI Exposures`                          | No        | Display name of the connector in OpenCTI.                                                        |
| Connector Scope | scope           | `CONNECTOR_SCOPE`           | `incident,vulnerability,ipv4-addr,ipv6-addr,domain-name` | No        | STIX object types imported by the connector.                                                     |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | `error`                                                  | No        | Log verbosity. Options: `debug`, `info`, `warn`, `warning`, `error`.                             |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | `PT1H`                                                   | No        | ISO-8601 interval between connector runs. Use `PT0S` for a one-shot run that exits after import. |


### Connector extra parameters environment variables

All connector-specific settings live under the `recorded-future-asi` key in `config.yml` or use the `RECORDED_FUTURE_ASI_`* prefix in Docker.


| Parameter             | config.yml            | Docker environment variable                 | Default                             | Mandatory | Description                                                                                                                                                                 |
| --------------------- | --------------------- | ------------------------------------------- | ----------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API base URL (v2)     | api_base_url          | `RECORDED_FUTURE_ASI_API_BASE_URL`          | `https://api.securitytrails.com/v2` | No        | v2 API base URL for initial sync (exposures list and assets).                                                                                                               |
| API base URL (v1)     | api_v1_base_url       | `RECORDED_FUTURE_ASI_API_V1_BASE_URL`       | `https://api.securitytrails.com/v1` | No        | v1 API base URL for incremental sync (exposure history activity).                                                                                                           |
| API key               | api_key               | `RECORDED_FUTURE_ASI_API_KEY`               | —                                   | Yes       | ASI API key for authentication.                                                                                                                                             |
| Project ID            | project_id            | `RECORDED_FUTURE_ASI_PROJECT_ID`            | —                                   | Yes       | ASI project ID to fetch exposures from.                                                                                                                                     |
| TLP level             | tlp_level             | `RECORDED_FUTURE_ASI_TLP_LEVEL`             | `amber+strict`                      | No        | Default TLP marking applied to imported entities. Values: `clear`, `white`, `green`, `amber`, `amber+strict`, `red`.                                                        |
| Portal base URL       | portal_base_url       | `RECORDED_FUTURE_ASI_PORTAL_BASE_URL`       | —                                   | No        | Optional Recorded Future portal base URL for external-reference deep links to the ASI project overview.                                                                     |
| Page limit            | page_limit            | `RECORDED_FUTURE_ASI_PAGE_LIMIT`            | `100`                               | No        | Number of exposures (or assets) fetched per API page. Range: 1–1000.                                                                                                        |
| Run limit             | run_limit             | `RECORDED_FUTURE_ASI_RUN_LIMIT`             | — (no limit)                        | No        | Maximum exposures processed per connector run during initial sync. When set, the connector resumes from a stored cursor on subsequent runs until the full list is imported. |
| Retry max attempts    | retry_max_attempts    | `RECORDED_FUTURE_ASI_RETRY_MAX_ATTEMPTS`    | `3`                                 | No        | Maximum HTTP request attempts (including the first) before giving up. Range: 1–10.                                                                                          |
| Retry initial seconds | retry_initial_seconds | `RECORDED_FUTURE_ASI_RETRY_INITIAL_SECONDS` | `1`                                 | No        | Initial exponential backoff delay in seconds for retried requests. Range: 0.1–30.                                                                                           |
| Retry max seconds     | retry_max_seconds     | `RECORDED_FUTURE_ASI_RETRY_MAX_SECONDS`     | `60`                                | No        | Maximum backoff delay in seconds between retry attempts. Range: 1–300.                                                                                                      |
| Filter severity min   | filter_severity_min   | `RECORDED_FUTURE_ASI_FILTER_SEVERITY_MIN`   | —                                   | No        | Only import exposures at or above this severity. Values: `unknown`, `informational`, `moderate`, `critical`. Mutually exclusive with `filter_severity_exact`.               |
| Filter severity exact | filter_severity_exact | `RECORDED_FUTURE_ASI_FILTER_SEVERITY_EXACT` | —                                   | No        | Only import exposures matching this severity exactly. Same values as above. Mutually exclusive with `filter_severity_min`.                                                  |


## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-recorded-future-asi:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-recorded-future-asi:
    image: opencti/connector-recorded-future-asi:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Recorded Future ASI Exposures
      - CONNECTOR_SCOPE=incident,vulnerability,ipv4-addr,ipv6-addr,domain-name
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT1H
      - RECORDED_FUTURE_ASI_API_BASE_URL=https://api.securitytrails.com/v2
      - RECORDED_FUTURE_ASI_API_V1_BASE_URL=https://api.securitytrails.com/v1
      - RECORDED_FUTURE_ASI_API_KEY=ChangeMe
      - RECORDED_FUTURE_ASI_PROJECT_ID=ChangeMe
      - RECORDED_FUTURE_ASI_TLP_LEVEL=amber+strict
      - RECORDED_FUTURE_ASI_PAGE_LIMIT=100
      - RECORDED_FUTURE_ASI_RETRY_MAX_ATTEMPTS=3
      - RECORDED_FUTURE_ASI_RETRY_INITIAL_SECONDS=1
      - RECORDED_FUTURE_ASI_RETRY_MAX_SECONDS=60
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.
2. Install dependencies:

```bash
pip3 install -r src/requirements.txt
```

1. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

After installation, the connector runs automatically at the interval defined by `duration_period` / `CONNECTOR_DURATION_PERIOD` (default: every hour).

To force an immediate re-run without waiting for the scheduler, go to **Data management → Ingestion → Connectors** in OpenCTI, find the connector, and click the refresh button. This resets the connector state and triggers a new import from scratch (initial sync).

To run the connector once and exit (useful for cron-based scheduling), set `CONNECTOR_DURATION_PERIOD=PT0S`.

## Behavior

### Sync modes

The connector operates in two phases:

1. **Initial sync** — Until `last_fetch_time` is stored in connector state, the connector paginates the v2 exposures list (`GET /projects/{project_id}/exposures`) for the configured project. For each exposure, it fetches associated assets (`GET /projects/{project_id}/exposures/{signature_id}`) and builds a STIX bundle.
2. **Incremental sync** — After the initial cycle completes, subsequent runs query v1 exposure history activity (`GET /asi/rules/history/{project_id}/activity`) starting from `last_fetch_time`. Added rules are enriched with v2 asset data; removed rules emit a cleared incident update without re-fetching assets.

### Connector state

State is persisted after a successful collection cycle, including runs that produce no STIX objects to send:


| State key          | Description                                                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `last_fetch_time`  | Unix timestamp marking the incremental sync watermark. Set when the initial v2 list cycle completes, then updated after each incremental run. |
| `exposures_cursor` | Pagination cursor for resuming initial sync when `run_limit` is configured. Cleared when the initial cycle completes.                         |
| `last_run`         | Human-readable UTC timestamp of the last successful run.                                                                                      |


If a run fails, state is not advanced, so the next run retries from the last successful position.

### STIX objects produced

For each **added** exposure, the connector creates:

- **Incident** — Type `Attack Surface Monitoring`, label `recorded-future-asi:added`, deterministic ID keyed on the RF exposure ID
- **Observables** — IPv4 addresses, IPv6 addresses, and domain names derived from affected assets
- **Vulnerabilities** — CVEs linked from exposure signatures (with CVSS, EPSS, and CWE labels when available)
- **Relationships** — `related-to` from incident to observables and vulnerabilities and from observables to vulnerabilities
- **Author and TLP marking** — Organization author `Recorded Future ASI` and the configured TLP marking

For **cleared** exposures (removed in incremental history), the connector sends an incident-only update with label `recorded-future-asi:cleared` and the same deterministic incident ID, allowing OpenCTI to update the existing incident.

Optional `portal_base_url` adds an external reference deep link to the ASI project overview in the Recorded Future portal.

### Severity mapping

RF ASI severities are mapped to OpenCTI incident severity as follows:


| RF ASI severity    | OpenCTI severity |
| ------------------ | ---------------- |
| `critical`, `high` | `critical`       |
| `moderate`         | `medium`         |
| `informational`    | `low`            |
| `unknown`          | `low`            |


Optional `filter_severity_min` and `filter_severity_exact` settings apply during both initial list fetch (via API query parameters) and incremental history processing (client-side filtering). Only one filter may be configured at a time.

### Batching and rate limiting

When `run_limit` is set, the connector imports at most that many exposures per run during initial sync, stores `exposures_cursor`, and resumes on the next scheduled run until the full list is processed. Only then is `last_fetch_time` set and incremental sync begins.

HTTP requests retry automatically on `429` (honoring `Retry-After` when present) and `5xx` responses, with configurable exponential backoff (`retry_max_attempts`, `retry_initial_seconds`, `retry_max_seconds`).

Bundles are sent with `cleanup_inconsistent_bundle=True` so OpenCTI workers can reconcile duplicate references within a bundle.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` (or `log_level: debug` in `config.yml`) for verbose connector and API client logs, including sync mode, exposure counts, and retry attempts.

Logging messages use the connector helper logger, for example:

```python
self.helper.connector_logger.error("An error message")
```

Common issues:

- **401 Unauthorized** — Verify `RECORDED_FUTURE_ASI_API_KEY` and that the key has access to the configured project.
- **No data imported** — Confirm `RECORDED_FUTURE_ASI_PROJECT_ID` matches an active ASI project with exposures. Check severity filters are not excluding all findings.
- **Initial sync never completes** — When using `run_limit`, multiple runs are expected before incremental sync starts. Monitor `exposures_cursor` in connector state.

## Additional information

### API endpoints


| Phase        | Method | Endpoint                                                        |
| ------------ | ------ | --------------------------------------------------------------- |
| Initial sync | GET    | `{api_base_url}/projects/{project_id}/exposures`                |
| Asset detail | GET    | `{api_base_url}/projects/{project_id}/exposures/{signature_id}` |
| Incremental  | GET    | `{api_v1_base_url}/asi/rules/history/{project_id}/activity`     |


Default base URLs point to the Recorded Future ASI API (`api.securitytrails.com`).

### Rate limits

The API client retries transient failures (HTTP 429 and 5xx) with exponential backoff. On HTTP 429, the client honors the `Retry-After` response header when present. Tune retry settings if you operate in a rate-limited environment.

### Related Documentation

- [Connector configuration reference](__metadata__/CONNECTOR_CONFIG_DOC.md)

