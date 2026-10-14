# Flowtriq DDoS Incidents Connector for OpenCTI

This connector imports DDoS attack incident data from the [Flowtriq](https://flowtriq.com) network monitoring platform into OpenCTI as STIX 2.1 threat intelligence.

## Overview

Flowtriq detects volumetric DDoS attacks in real time using NetFlow and sFlow analysis. This connector periodically polls the Flowtriq REST API to retrieve incident records and converts them into STIX objects that can be correlated with other threat intelligence in OpenCTI.

### What gets imported

For each DDoS incident, the connector creates:

- **IPv4/IPv6 Observables** for attack target IPs
- **Indicator objects** with STIX patterns for each target IP (optional, enabled by default)
- **Source IP Observables and Indicators** when Service Port source data is available
- **Relationships** linking indicators to their observables

Attack metadata is preserved as labels and descriptions:
- Attack type (e.g., `ddos:syn-flood`, `ddos:udp-flood`, `ddos:dns-amplification`)
- Severity level (`severity:critical`, `severity:high`, etc.)
- Peak volume (PPS and BPS)
- Timestamps (start, end, duration)

## Requirements

- OpenCTI >= 6.5.1
- A Flowtriq account with API access (deploy token)

## Configuration

The connector can be configured via environment variables or a `config.yml` file.

### Required parameters

| Parameter | Environment variable | Description |
| --------- | -------------------- | ----------- |
| OpenCTI URL | `OPENCTI_URL` | The URL of your OpenCTI instance |
| OpenCTI Token | `OPENCTI_TOKEN` | API token for OpenCTI |
| Connector ID | `CONNECTOR_ID` | A unique UUID v4 for this connector instance |
| Flowtriq API Key | `FLOWTRIQ_API_KEY` | Your Flowtriq deploy token (64-character hex string) |

### Optional parameters

| Parameter | Environment variable | Default | Description |
| --------- | -------------------- | ------- | ----------- |
| Connector Name | `CONNECTOR_NAME` | `Flowtriq DDoS Incidents` | Display name in OpenCTI |
| Connector Scope | `CONNECTOR_SCOPE` | `flowtriq` | Connector scope identifier |
| Log Level | `CONNECTOR_LOG_LEVEL` | `info` | Minimum log level |
| Duration Period | `CONNECTOR_DURATION_PERIOD` | `PT1H` | Polling interval in ISO 8601 duration format |
| API URL | `FLOWTRIQ_API_URL` | `https://app.flowtriq.com` | Flowtriq API base URL |
| Incident Status | `FLOWTRIQ_INCIDENT_STATUS` | `resolved` | Filter by status: `active`, `resolved`, `false_positive`, or empty for all |
| Incident Severity | `FLOWTRIQ_INCIDENT_SEVERITY` | (all) | Comma-separated severity filter |
| Create Indicators | `FLOWTRIQ_CREATE_INDICATOR` | `true` | Create STIX Indicator objects alongside observables |
| TLP Level | `FLOWTRIQ_TLP_LEVEL` | `green` | TLP marking: `clear`, `green`, `amber`, `amber+strict`, `red` |
| Import Limit | `FLOWTRIQ_IMPORT_LIMIT` | `100` | Maximum incidents to fetch per run |
| Min Severity | `FLOWTRIQ_MIN_SEVERITY` | (none) | Skip incidents below this severity level |

## Deployment

### Docker Compose

```yaml
services:
  connector-flowtriq:
    image: opencti/connector-flowtriq:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${FLOWTRIQ_CONNECTOR_ID}
      - CONNECTOR_NAME=Flowtriq DDoS Incidents
      - CONNECTOR_SCOPE=flowtriq
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - FLOWTRIQ_API_KEY=${FLOWTRIQ_API_KEY}
      - FLOWTRIQ_CREATE_INDICATOR=true
      - FLOWTRIQ_TLP_LEVEL=green
    restart: always
```

### Manual

```bash
pip install -r src/requirements.txt
cd src && python main.py
```

## How it works

1. The connector authenticates to the Flowtriq API using a Bearer token (deploy token).
2. On each scheduled run, it fetches incidents via `GET /api/v1/incidents` with configured filters.
3. For each incident, it fetches extended detail (source IP data) via `GET /api/v1/incidents/{uuid}`.
4. Incidents are filtered by severity threshold and deduplication against previously seen timestamps.
5. Target IPs and source IPs are converted to STIX IPv4Address/IPv6Address observables.
6. If `create_indicator` is enabled, STIX Indicator objects with patterns like `[ipv4-addr:value = '1.2.3.4']` are created and linked to observables via `based-on` relationships.
7. The STIX bundle is submitted to OpenCTI via `send_stix2_bundle()`.
8. The connector state (last run timestamp) is persisted for deduplication on subsequent runs.

## Getting a Flowtriq API key

1. Log in to your Flowtriq dashboard at `https://app.flowtriq.com`
2. Navigate to **Settings > API**
3. Generate or copy your deploy token
4. Use this 64-character token as the `FLOWTRIQ_API_KEY` value
