# OpenCTI Lab539 AiTM Feed Connector

## Overview

This connector integrates the [Lab539 AiTM Feed](https://www.aitmfeed.com) with OpenCTI, importing Adversary-in-the-Middle (AiTM) phishing infrastructure as STIX 2.1 indicators and observables.

The Lab539 AiTM Feed provides real-time threat intelligence on active AiTM phishing infrastructure, including IP addresses, domains, ASN data, and confidence scores. Each detection event is imported as an indicator with linked IPv4/IPv6 address and domain name observables, marked TLP:AMBER.

## Requirements

- OpenCTI >= 6.4.0
- A Lab539 AiTM Feed API key — [subscribe here](https://www.aitmfeed.com/subscribe)

## Data Model

Each feed record produces the following STIX objects in OpenCTI:

| Object | Type | Description |
|--------|------|-------------|
| Indicator | `indicator` | STIX pattern combining IP and domain, with confidence score and detection metadata |
| IP Address | `ipv4-addr` / `ipv6-addr` | The infrastructure IP address |
| Domain Name | `domain-name` | The hostname or domain associated with the infrastructure |

All objects are marked **TLP:AMBER** and authored by **Lab539**.

### Custom Properties

The following Lab539-specific properties are included on each indicator:

| Property | Description |
|----------|-------------|
| `x_lab539_eventid` | Unique event identifier |
| `x_lab539_asn` | ASN and organisation of the IP address |
| `x_lab539_country` | Country code of the IP address |
| `x_lab539_frontend` | Whether the infrastructure was acting as AiTM frontend (phishing) |
| `x_lab539_backend` | Whether the infrastructure was acting as AiTM backend (credential relay) |
| `x_lab539_active` | Whether the infrastructure was active at time of detection |
| `x_lab539_rdns` | Reverse DNS entry for the IP address |
| `x_lab539_detected` | Timestamp when the infrastructure was first detected |
| `x_lab539_timestamp` | Timestamp of the most recent detection event |

## Configuration

| Parameter | Docker environment variable | Default | Description |
|-----------|-----------------------------|---------|-------------|
| OpenCTI URL | `OPENCTI_URL` | | URL of your OpenCTI instance |
| OpenCTI Token | `OPENCTI_TOKEN` | | Your OpenCTI API token |
| Connector ID | `CONNECTOR_ID` | | Unique UUID for this connector instance |
| Connector Name | `CONNECTOR_NAME` | `Lab539 AiTM Feed` | Display name in OpenCTI |
| Connector Scope | `CONNECTOR_SCOPE` | `ipv4-addr,ipv6-addr,domain-name` | STIX observable types |
| Log Level | `CONNECTOR_LOG_LEVEL` | `info` | Logging verbosity |
| Run Interval | `CONNECTOR_DURATION_PERIOD` | `PT15M` | ISO 8601 duration between runs |
| AiTM API Key | `AITM_FEED_API_KEY` | | Your Lab539 AiTM Feed API key |
| AiTM API URL | `AITM_FEED_API_BASE_URL` | `https://aitm.lab539.io/v1.0` | AiTM Feed API base URL |
| TLP Level | `AITM_FEED_TLP_LEVEL` | `amber` | TLP marking (`white`, `green`, `amber`, `amber+strict`, `red`) |
| Lookback Days | `AITM_FEED_FIRST_RUN_LOOKBACK_DAYS` | `7` | Days of history to import on first run |

## Deployment

**1. Pull the Docker image**

```bash
docker pull lab539/opencti-aitm-feed-connector:latest
```

**2. Create a `.env` file with your credentials**

```
OPENCTI_TOKEN=your-opencti-api-token
CONNECTOR_ID=your-generated-uuid
AITM_FEED_API_KEY=your-aitm-feed-api-key
```

Generate a UUID with:
```bash
cat /proc/sys/kernel/random/uuid
```

**3. Create a `docker-compose.yml`**

```yaml
services:
  connector-lab539-aitm-feed:
    image: lab539/opencti-aitm-feed-connector:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_ID}
      - CONNECTOR_NAME=Lab539 AiTM Feed
      - CONNECTOR_SCOPE=ipv4-addr,ipv6-addr,domain-name
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT15M
      - CONNECTOR_QUEUE_THRESHOLD=500
      - AITM_FEED_API_KEY=${AITM_FEED_API_KEY}
      - AITM_FEED_API_BASE_URL=https://aitm.lab539.io/v1.0
      - AITM_FEED_TLP_LEVEL=amber
      - AITM_FEED_FIRST_RUN_LOOKBACK_DAYS=7
    restart: unless-stopped
    networks:
      - xtm_default

networks:
  xtm_default:
    external: true
```

**4. Start the connector**

```bash
docker compose up -d
```

The connector will register with OpenCTI, import the last 7 days of AiTM feed data on first run, then poll for new records on the configured interval.

## Behaviour

- **First run**: imports all records from the configured lookback window (default 7 days)
- **Subsequent runs**: imports only records with a timestamp newer than the previous run
- **Deduplication**: STIX IDs are deterministically generated from the Lab539 `eventid`, so re-importing the same record is always a silent upsert — no duplicates
- **Pre-check**: each run calls the lightweight `/last-event` endpoint before fetching the full dataset, skipping the API call entirely if no new data is available

## Further Documentation

Full integration documentation is available at [docs.aitmfeed.com/integrations/opencti](https://docs.aitmfeed.com/integrations/opencti).
