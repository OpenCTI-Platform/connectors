# OpenCTI TruKno Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | - | Initial port from standalone TruKno connector |

The TruKno connector imports breach intelligence from the TruKno API into OpenCTI as STIX 2.1 bundles.

## Scope

This initial port currently imports only:

- `report`
- `attack-pattern`
- `malware`

It does not yet create threat actors, intrusion sets, indicators, vulnerabilities, tools, or relationships beyond report object references.

## Installation

### Requirements

| Dependency       | Version                                    |
|------------------|--------------------------------------------|
| OpenCTI Platform | >= 7.x (tested on 7.260904.0)              |
| pycti            | == 7.260904.0                              |
| connectors-sdk   | GitHub `master` (repository subdirectory) |
| requests         | ~= 2.33.0                                  |
| Python           | 3.12 (Docker image)                        |

- Network access to the TruKno API
- A valid TruKno API key

## Configuration

The connector uses the `connectors-sdk` settings contract. Configure it with
environment variables through `docker-compose.yml` or a root-level `config.yml`
copied from `config.yml.sample`; environment variables take precedence.

At minimum you must supply:

- `OPENCTI_URL`
- `OPENCTI_TOKEN`
- `TRUKNO_API_KEY`

`CONNECTOR_ID` (a unique UUID for this connector instance) is also required at
runtime. For manual or `docker-compose` deployments you must set it yourself.
The OpenCTI Connector Manager injects it, so it is intentionally absent from
the Manager schema.

The remaining variables are optional and fall back to the defaults documented in `__metadata__/connector_config_schema.json`:

- `CONNECTOR_NAME` (default `TruKno`)
- `CONNECTOR_SCOPE` (default `report,attack-pattern,malware`)
- `CONNECTOR_TYPE` (default `EXTERNAL_IMPORT`)
- `CONNECTOR_LOG_LEVEL` (default `error`)
- `CONNECTOR_DURATION_PERIOD` (default `PT1H`, ISO 8601 duration)
- `TRUKNO_API_BASE_URL` (default `https://api.trukno.com/v2`)
- `TRUKNO_INITIAL_LOOKBACK_DAYS` (default `30`)

`TRUKNO_API_KEY` is a secret setting. The connector sends it as
`Authorization: Bearer <key>`; an already-prefixed `Bearer <key>` value is
accepted without adding a second prefix.

### Configuration Migration

`TRUKNO_CONNECTOR_CONFIG` is no longer supported. If this environment variable
is non-empty, settings construction and startup fail explicitly without logging
its configured path or configuration values. Unset it and move configuration to
the connector-root `config.yml` using `config.yml.sample`, or use environment
variables. The connector does not load configuration from the legacy custom path.

`CONNECTOR_DURATION_PERIOD` is the canonical scheduling setting and should be
used for all new deployments. `TRUKNO_INTERVAL_MINUTES` remains accepted only
to migrate existing runtime configuration: its value is converted to the
equivalent duration and emits a deprecation warning. When both are supplied,
the canonical `CONNECTOR_DURATION_PERIOD` value takes precedence.
The legacy interval must still be a positive integer even when the canonical
duration is set. Boolean, floating-point, fractional, blank, and non-numeric
values are rejected rather than coerced.

Additional metadata for Connector Manager and operator documentation is available in:

- `__metadata__/CONNECTOR_CONFIG_DOC.md`
- `__metadata__/connector_config_schema.json`

## Deployment

### Connector Manager Deployment

The TruKno connector supports deployment through OpenCTI Connector Manager.
Configure the required OpenCTI connection and `TRUKNO_API_KEY` through the
Manager form. The Manager injects `CONNECTOR_ID`; do not add it to the Manager
configuration. Use `CONNECTOR_DURATION_PERIOD` to select the run frequency.

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-trukno:latest .
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` from `config.yml.sample` and set `connector.id`.
2. Install dependencies and start the connector from the connector root:

```bash
uv run --python 3.12 --with-requirements src/requirements.txt python src/main.py
```

## Behavior

The connector polls the TruKno `/breaches/list` endpoint in daily windows. It
queries both `hasTTPs=true` and `hasTTPs=false` result partitions, paginates
through each response, deduplicates by breach ID, and filters results whose
publication `date` is newer than the import checkpoint. After the initial
backfill, scans begin with a one-day overlap from the last successful scan so
API work stays bounded while tolerating short publication delays when the
returned publication timestamp is newer than the import checkpoint. The
connector then fetches `/breaches/{id}` details for each match, converts the
result to a STIX bundle, and sends the bundle to OpenCTI.

The current TruKno v2 schema does not expose a breach update timestamp. The
connector therefore tracks publication dates and queries only the initial
backfill or the latest one-day overlap. It cannot detect changes to an older
breach or a record first exposed after its publication date falls outside that
query window. A record with a publication timestamp equal to or older than
`last_seen_updated_at` is also filtered as already processed. Covering these
cases requires an API update timestamp or stable change feed.

### Incremental State

- `last_seen_updated_at` stores the latest publication timestamp from a fully
  processed batch.
- `last_successful_scan_at` advances after every successful scan, including an
  empty scan, and bounds the next query with a one-day overlap.
- On a first run without state, the connector backfills from `now - TRUKNO_INITIAL_LOOKBACK_DAYS`.
- Existing state containing only `last_seen_updated_at` remains compatible and
  uses that timestamp as the first scan boundary after upgrade.
- A failed fetch, transform, or send advances neither watermark, so the batch is
  retried on the next cycle.

### Entity Mapping

| TruKno field | OpenCTI / STIX object | Notes |
|--------------|------------------------|-------|
| breach | `report` | One report per TruKno breach |
| `relatedTTPs` | `attack-pattern` | Linked from the report via `object_refs` |
| `relatedMalwares` | `malware` | Linked from the report via `object_refs` |

## Usage

The connector runs continuously on the configured polling interval.

To force a new import cycle, reset the connector state from the OpenCTI connectors UI and let the next scheduled poll run.

## Upstream Status

This first upstream submission intentionally limits scope to reports, attack patterns, and malware so the connector can land with a narrow and reviewable ingestion path before broader entity coverage is added.
