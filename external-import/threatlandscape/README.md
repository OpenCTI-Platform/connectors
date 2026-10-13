# Threat Landscape Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner | -    | -       |

Imports continuously updated STIX 2.1 threat intelligence bundles from [Threat Landscape](https://threatlandscape.io) into OpenCTI. Data is collected from both open-source intelligence (OSINT) and darknet sources and delivered as fully-formed STIX 2.1 bundles — no conversion is performed by this connector.

## Description

The Threat Landscape API exposes a continuously growing feed of threat intelligence as pre-built STIX 2.1 bundles. Each bundle contains a `report` as the primary context object, linked to relevant SDOs including threat actors, malware families, campaigns, intrusion sets, indicators of compromise, vulnerabilities, attack patterns, locations, and identities — all interconnected via STIX `relationship` objects.

This connector:

- Fetches new bundles on a configurable schedule (default: every hour).
- On the **first run**, imports all bundles published within a configurable lookback window (default: 30 days).
- On **subsequent runs**, fetches only bundles with a `seq_id` greater than the last seen cursor, ensuring no duplicates and no missed data.
- Optionally filters to a single source type (`osint` or `darknet`).

## Requirements

- OpenCTI Platform >= 6.8.12
- A Threat Landscape API key ([threatlandscape.io](https://threatlandscape.io))

## Configuration

### Docker

```yaml
environment:
  - OPENCTI_URL=http://localhost
  - OPENCTI_TOKEN=ChangeMe
  - CONNECTOR_ID=ChangeMe
  - CONNECTOR_NAME=Threat Landscape
  - CONNECTOR_SCOPE=indicator,report,threat-actor,malware,campaign,intrusion-set,attack-pattern,vulnerability,identity,location
  - CONNECTOR_LOG_LEVEL=info
  - CONNECTOR_DURATION_PERIOD=PT1H
  - THREATLANDSCAPE_API_KEY=ChangeMe
  - THREATLANDSCAPE_IMPORT_SINCE=P30D
  - THREATLANDSCAPE_FEED=intelligence
  - THREATLANDSCAPE_PAGE_SIZE=100
```

### Local

Copy `config.yml.sample` to `config.yml` and fill in your values:

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'ChangeMe'

connector:
  id: 'ChangeMe'
  name: 'Threat Landscape'
  scope: 'indicator,report,threat-actor,malware,campaign,intrusion-set,attack-pattern,vulnerability,identity,location'
  log_level: 'info'
  duration_period: 'PT1H'

threatlandscape:
  api_key: 'ChangeMe'
  import_since: 'P30D'
```

## Configuration Parameters

| Parameter | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `opencti.url` | `OPENCTI_URL` | — | Yes | OpenCTI platform URL |
| `opencti.token` | `OPENCTI_TOKEN` | — | Yes | OpenCTI API token |
| `connector.id` | `CONNECTOR_ID` | — | Yes | Unique UUIDv4 for this connector instance |
| `connector.name` | `CONNECTOR_NAME` | `Threat Landscape` | No | Display name in OpenCTI |
| `connector.scope` | `CONNECTOR_SCOPE` | — | Yes | STIX object types to import |
| `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | No | Log verbosity: `debug`, `info`, `warning`, `error` |
| `connector.duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT1H` | No | ISO 8601 interval between runs |
| `threatlandscape.api_base_url` | `THREATLANDSCAPE_API_BASE_URL` | `https://api.threatlandscape.io/rest/v1` | No | API base URL |
| `threatlandscape.api_key` | `THREATLANDSCAPE_API_KEY` | — | Yes | Threat Landscape API key |
| `threatlandscape.import_since` | `THREATLANDSCAPE_IMPORT_SINCE` | `P30D` | No | Lookback window for the first run (ISO 8601 duration) |
| `threatlandscape.feed` | `THREATLANDSCAPE_FEED` | — | Yes | `intelligence` (both sources), `intelligence-osint`, `intelligence-darknet`, or `ioc` |
| `threatlandscape.page_size` | `THREATLANDSCAPE_PAGE_SIZE` | `100` | No | Bundles fetched per API request (1–1000) |

## Installation

### Docker

```bash
docker compose up -d
```

### Local

```bash
cd external-import/threatlandscape
python3 -m venv venv
source venv/bin/activate
pip install -r src/requirements.txt
cp config.yml.sample config.yml
# Edit config.yml with your credentials
python src/main.py
```

## Behaviour

- **First run:** fetches all bundles with `stix_published_at >= now - import_since`, ordered by `seq_id` ascending. Large lookback windows (e.g. `P365D`) will ingest many bundles in batches of 5,000 STIX objects.
- **Subsequent runs:** fetches only bundles with `seq_id > last_seq_id`. Typically a small number per hourly run.
- **State:** the highest `seq_id` seen is persisted in OpenCTI connector state after each successful run. If a run fails, state is not updated and the next run will retry from the last successful cursor.
- **Deduplication:** OpenCTI deduplicates all incoming objects by deterministic ID. Re-sending the same bundle is safe.

## Additional Resources

- [Threat Landscape API Documentation](https://threatlandscape.io)
- [OpenCTI Documentation](https://docs.opencti.io)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
