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

| Dependency       | Version                        |
|------------------|--------------------------------|
| OpenCTI Platform | >= 7.x (tested on 7.260609.0)  |
| pycti            | == 7.260609.0                  |
| PyYAML           | ~= 6.0.2                       |
| requests         | ~= 2.32.3                      |
| Python           | 3.12 (Docker image)            |

- Network access to the TruKno API
- A valid TruKno API key

## Configuration

The connector can be configured with environment variables through `docker-compose.yml` or with `src/config.yml`.

At minimum you must supply:

- `OPENCTI_URL`
- `OPENCTI_TOKEN`
- `TRUKNO_API_KEY`

`CONNECTOR_ID` (a unique UUID for this connector instance) is also required at runtime. For manual or `docker-compose` deployments you must set it yourself; when the connector is deployed through the OpenCTI Connector Manager it is generated and injected automatically, which is why it is not listed as `required` in `__metadata__/connector_config_schema.json`.

The remaining variables are optional and fall back to the defaults documented in `__metadata__/connector_config_schema.json`:

- `CONNECTOR_NAME` (default `TruKno`)
- `CONNECTOR_SCOPE` (default `report,attack-pattern,malware`)
- `CONNECTOR_TYPE` (default `EXTERNAL_IMPORT`)
- `CONNECTOR_LOG_LEVEL` (default `info`)
- `TRUKNO_API_BASE_URL` (default `https://api.trukno.com/v2`)
- `TRUKNO_INTERVAL_MINUTES` (default `60`)
- `TRUKNO_INITIAL_LOOKBACK_DAYS` (default `30`)

Additional metadata for Connector Manager and operator documentation is available in:

- `__metadata__/CONNECTOR_CONFIG_DOC.md`
- `__metadata__/connector_config_schema.json`

## Deployment

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

1. Create `src/config.yml` from `src/config.yml.sample`.
2. Install dependencies from `src/requirements.txt`.
3. Start the connector from the `src` directory:

```bash
pip3 install -r requirements.txt
python3 main.py
```

## Behavior

The connector polls the TruKno `/breaches` endpoint for items updated after the last stored checkpoint, fetches full breach details for each match, converts the result to a STIX bundle, and sends the bundle to OpenCTI.

### Incremental State

- State is stored in OpenCTI as `last_seen_updated_at`.
- On a first run without state, the connector backfills from `now - TRUKNO_INITIAL_LOOKBACK_DAYS`.
- Each successfully sent breach advances the checkpoint.

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
