# OpenCTI Abuse.ch False Positive List Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

This connector fetches the [abuse.ch Hunting](https://hunting.abuse.ch/) False Positive List and removes matching Indicators from OpenCTI.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
  - [OpenCTI environment variables](#opencti-environment-variables)
  - [Base connector environment variables](#base-connector-environment-variables)
  - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Local Development](#local-development)
- [Behavior](#behavior)
- [Debugging](#debugging)

## Introduction

The abuse.ch Hunting platform maintains a curated False Positive List of IOCs that were erroneously submitted to MalwareBazaar, ThreatFox, or other abuse.ch platforms. This connector periodically fetches that list and deletes the corresponding Indicators from OpenCTI, preventing false alerts in downstream SIEM/EDR integrations.

Each run only processes entries newer than the last seen `removal_id`, which is persisted in OpenCTI's connector state across restarts.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- abuse.ch Auth-Key (free registration at [abuse.ch Authentication Portal](https://auth.abuse.ch/))

## Configuration variables

### OpenCTI environment variables

| Parameter | config.yml | Docker environment variable | Mandatory | Description |
|-----------|------------|-----------------------------|-----------|-------------|
| OpenCTI URL | url | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform. |
| OpenCTI Token | token | `OPENCTI_TOKEN` | Yes | The token of the user representing the connector in the OpenCTI platform. |
| OpenCTI SSL Verify | ssl_verify | `OPENCTI_SSL_VERIFY` | No | Whether to verify the SSL certificate of the OpenCTI platform (default: `true`). |

### Base connector environment variables

| Parameter | config.yml | Docker environment variable | Default | Mandatory | Description |
|-----------|------------|-----------------------------|---------|-----------|-------------|
| Connector ID | id | `CONNECTOR_ID` | / | Yes | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name | name | `CONNECTOR_NAME` | `AbusechFplist` | No | Name of the connector as shown in OpenCTI. |
| Connector Scope | scope | `CONNECTOR_SCOPE` | `indicator` | No | The scope of the connector. |
| Log Level | log_level | `CONNECTOR_LOG_LEVEL` | `error` | No | Determines the verbosity of the logs. Options: `debug`, `info`, `warn`, `error`. |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | `P1D` | No | Interval between two runs, in ISO-8601 format (e.g. `PT6H` = every 6 hours). |

### Connector extra parameters environment variables

| Parameter | config.yml | Docker environment variable | Default | Mandatory | Description |
|-----------|------------|-----------------------------|---------|-----------|-------------|
| API Base URL | api_base_url | `ABUSECH_FPLIST_API_BASE_URL` | `https://hunting-api.abuse.ch/api/v1/` | No | Hunting API endpoint. |
| API Key | api_key | `ABUSECH_FPLIST_API_KEY` | / | Yes | Your abuse.ch Auth-Key from the [Authentication Portal](https://auth.abuse.ch/). |
| Dry Run | dry_run | `ABUSECH_FPLIST_DRY_RUN` | `false` | No | If `true`, log which Indicators would be deleted without actually deleting them. |

## Deployment

### Docker Deployment

Build the image:

```bash
docker build -t opencti/connector-abusech-fplist:latest .
```

Run with `docker compose` (recommended for production):

```bash
docker compose up -d
```

### Local Development

Build the image and run a single execution with `docker run`:

```bash
docker build -t connector-abusech-fplist:latest .

docker run --rm \
  -e OPENCTI_URL=http://host.docker.internal:8080 \
  -e OPENCTI_TOKEN=your-opencti-token \
  -e CONNECTOR_ID=$(python3 -c "import uuid; print(uuid.uuid4())") \
  -e CONNECTOR_LOG_LEVEL=debug \
  -e ABUSECH_FPLIST_API_KEY=your-api-key \
  connector-abusech-fplist:latest
```

Alternatively, copy `config.yml.sample` to `src/config.yml`, fill in your values and mount it (the connector picks it up automatically; env vars take precedence):

```bash
docker run --rm \
  -v $(pwd)/src/config.yml:/opt/opencti-connector-abusech-fplist/config.yml \
  connector-abusech-fplist:latest
```

## Behavior

On each run the connector:

1. Reads `last_removal_id` from the connector state stored in OpenCTI (0 on first run).
2. Fetches the full False Positive List from the Hunting API (CSV format).
3. Filters entries with `removal_id > last_removal_id` and processes them oldest-first.
4. For each entry, searches OpenCTI for the matching Indicators by STIX pattern and deletes them if found.
5. Saves the highest processed `removal_id` back to the connector state, so the next run skips entries that were already processed. The state is only advanced after a fully successful run (and never in dry run mode): if a run fails, its entries are retried on the next run — deletions are idempotent.

> [!WARNING]
> Deletion is pattern-based. OpenCTI Indicators have deterministic ids derived from their pattern, so an Indicator whose pattern matches a false positive entry is deleted even if other (non abuse.ch) sources contributed to it. Run the connector with `ABUSECH_FPLIST_DRY_RUN=true` first to review what would be deleted.

### Supported IOC types

Some types are looked up with several candidate patterns, to match the different
pattern styles used by the abuse.ch feed connectors (URLhaus, ThreatFox, MalwareBazaar).
Every Indicator matching any of the candidates is deleted.

| `entry_type` | STIX patterns used for lookup |
|---|---|
| `sha256_hash` | `[file:hashes.'SHA-256' = '...']` |
| `md5_hash` | `[file:hashes.MD5 = '...']` |
| `sha1_hash` | `[file:hashes.'SHA-1' = '...']`, `[file:hashes.SHA1 = '...']` |
| `sha3_384` | `[file:hashes.'SHA3-384' = '...']` |
| `domain` | `[domain-name:value = '...']` |
| `url` | `[url:value = '...']` |
| `ip:port` (IPv4 only) | `[network-traffic:dst_ref.type = 'ipv4-addr' AND ...]`, `[ipv4-addr:value = '...']` |

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

To reprocess all entries from scratch, reset the connector state from OpenCTI UI:
**Data Management → Ingestion → Connectors** → find the connector → reset state.
