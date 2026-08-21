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


## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

### Datadog authentication

Datadog authentication for this endpoint uses [API Keys](https://app.datadoghq.com/organization-settings/api-keys) and a value sent in the `dd-application-key` header. You can use [Application Keys](https://app.datadoghq.com/organization-settings/application-keys) for that header; when you do, the key must include the `reference_table_write` scope or requests fail with `403 Forbidden`. Instead of using Application Keys, you can use [Personal Access Tokens](https://app.datadoghq.com/organization-settings/access-tokens). Personal Access Tokens are scoped and short-lived, so access is limited to the permissions you need and expires automatically.

## Deployment

### Docker Deployment

Before starting the connector, replace `CONNECTOR_LIVE_STREAM_ID=live` in `docker-compose.yml` with the dedicated stream ID created for this connector.

Set the required environment variables in a `.env` file alongside `docker-compose.yml`:

```shell
OPENCTI_TOKEN=<your-opencti-token>      # - DATADOG_INTEL_INDICATOR_TYPE=ip_address

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

In `config.yml`, replace `connector.live_stream_id: 'ChangeMe'` with the dedicated stream ID created for this connector.

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
| `403 Forbidden` on batch push | Application Key is missing the `reference_table_write` scope — regenerate it with that scope enabled |
| Connector visible in OpenCTI but no data in Datadog | Indicator type mismatch — verify `DATADOG_INTEL_INDICATOR_TYPE` includes the types present in your stream |
| Duplicate connector instance warnings | Two connectors running with the same `CONNECTOR_ID` — each instance needs a unique UUIDv4 |
