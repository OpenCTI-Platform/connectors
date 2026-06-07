# OpenCTI Connector — Datadog Threat Intel

Stream connector that forwards threat intelligence indicators from OpenCTI to the Datadog Threat Intelligence API. It listens to the OpenCTI live stream, batches indicator events, and POSTs them to the configured Datadog endpoint with gzip compression.

**Supported indicator types:** `ip_address`, `domain`, `sha256`

Table of Contents

- [OpenCTI Connector — Datadog Threat Intel](#opencti-connector--datadog-threat-intel)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)
    - [Forcing a full resend](#forcing-a-full-resend)
  - [Debugging](#debugging)

## Installation

### Requirements

- OpenCTI Platform >= 6.8.13
- A Datadog account with access to manage [Integrations](https://docs.datadoghq.com/integrations/)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter | config.yml | Docker env var | Mandatory | Description |
|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | Yes | URL of the OpenCTI platform |
| OpenCTI Token | `opencti.token` | `OPENCTI_TOKEN` | Yes | Admin token for the OpenCTI platform |

### Base connector environment variables

| Parameter | config.yml | Docker env var | Default | Mandatory | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | — | Yes | Unique UUIDv4 for this connector instance |
| Connector Name | `connector.name` | `CONNECTOR_NAME` | `DatadogIntelConnector` | No | Display name in OpenCTI |
| Connector Scope | `connector.scope` | `CONNECTOR_SCOPE` | — | Yes | Set to `indicator` |
| Log Level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn`, or `error` |
| Live Stream ID | `connector.live_stream_id` | `CONNECTOR_LIVE_STREAM_ID` | `live` | Yes | ID of the live stream in the OpenCTI UI |
| Listen Deletes | `connector.live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true` | No | Forward delete events to Datadog |
| No Dependencies | `connector.live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true` | No | Only forward the indicator itself, not related entities |

### Connector extra parameters environment variables

| Parameter | config.yml | Docker env var | Default | Mandatory | Description |
|---|---|---|---|---|---|
| API Base URL | `datadog_intel.integration_api_url` | `DATADOG_INTEL_INTEGRATION_API_URL` | — | Yes | Your Datadog site URL appended with `/api/v2/security/threat-intel-feed`. Example: if your Datadog site is `https://app.datadoghq.com`, use `https://app.datadoghq.com/api/v2/security/threat-intel-feed`. |
| Indicator Types | `datadog_intel.indicator_type` | `DATADOG_INTEL_INDICATOR_TYPE` | `["ip_address"]` | No | List of indicator types to forward. Accepted values: `ip_address`, `domain`, `sha256`. In config.yml use a YAML list; via env var use a JSON array (e.g. `["ip_address","domain"]`) |
| Datadog API Key | `datadog_intel.dd_api_key` | `DATADOG_INTEL_DD_API_KEY` | — | Yes | Datadog API key. Sent on every request as the `dd-api-key` header to authenticate against `integration_api_url` |
| Datadog Application Key | `datadog_intel.dd_application_key` | `DATADOG_INTEL_DD_APPLICATION_KEY` | — | Yes | Datadog application key. Sent on every request as the `dd-application-key` header to authenticate against `integration_api_url` |

## Deployment

### Docker Deployment

Set the required environment variables in a `.env` file alongside `docker-compose.yml`:

```shell
OPENCTI_TOKEN=<your-opencti-token>
CONNECTOR_ID=<uuidv4>
DATADOG_INTEL_INTEGRATION_API_URL=<datadog-endpoint>
DATADOG_INTEL_DD_API_KEY=<your-datadog-api-key>
DATADOG_INTEL_DD_APPLICATION_KEY=<your-datadog-application-key>
```

Build and start:

```shell
docker build . -t opencti/connector-datadog-intel:latest
docker compose up -d
```

### Manual Deployment

Copy and edit the sample config:

```shell
cp config.yml.sample config.yml
# edit config.yml with your values
```

Install dependencies and run from the `src/` directory:

```shell
pip install -r src/requirements.txt
python src/main.py
```

## Behavior

The connector subscribes to the OpenCTI live stream and processes `indicator` events in real time. Events are accumulated in an in-memory batch and flushed to the Datadog Threat Intel API when either:

- The batch reaches 10,000 indicators, or
- 30 seconds have elapsed since the last flush

Payloads are gzip-compressed before being sent. On transient failures the connector retries up to 5 times with exponential backoff (1s–60s with jitter). If the batch reaches the size limit while the endpoint is unreachable, it is dropped to prevent unbounded memory growth on the OpenCTI instance.

### Forcing a full resend

To resend all indicators from scratch — for example after a Datadog outage — assign a new UUIDv4 to `CONNECTOR_ID`. OpenCTI treats it as a fresh connector instance and replays the entire stream from the beginning.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to see per-event processing and batch flush details.

Common issues:

| Symptom | Likely cause |
|---|---|
| `Missing stream ID` on startup | `CONNECTOR_LIVE_STREAM_ID` is not set or still set to `ChangeMe` |
| `Failed to push batch after all retries` | Datadog endpoint unreachable or credentials invalid — check `DATADOG_INTEL_INTEGRATION_API_URL` |
| Connector visible in OpenCTI but no data in Datadog | Indicator type mismatch — verify `DATADOG_INTEL_INDICATOR_TYPE` includes the types present in your stream |
| Duplicate connector instance warnings | Two connectors running with the same `CONNECTOR_ID` — each instance needs a unique UUIDv4 |
