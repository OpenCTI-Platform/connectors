# OpenCTI Flare Connector
The Flare connector integrates OpenCTI with the Flare platform by ingesting events from a tenant feed as STIX 2.1 Incidents.
## Table of Contents
- [OpenCTI Flare Connector](#opencti-flare-connector)
    - [Table of Contents](#table-of-contents)
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

## Introduction
This connector fetches events from the Flare API and imports them into OpenCTI as Incidents with associated Indicator object, Observables and metadata such as severity, incident type and relevant dates.

## Installation
### Requirements
- Flare API Key

## Configuration variables
There are a number of configuration options, which are set either in `docker-compose.yml` (for deploying in the same compose as OpenCTI) or in `config.yml` (for manual deployment).

### OpenCTI environment variables
| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
| ------------- | ------------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | opencti.url   | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | opencti.token | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables
| Parameter        | config.yml                | Docker environment variable | Default | Mandatory | Description                                                               |     |
| ---------------- | ------------------------- | --------------------------- | ------- | --------- | ------------------------------------------------------------------------- | --- |
| Connector ID     | connector.id              | `CONNECTOR_ID`              |         | Yes       | A unique `UUIDv4` identifier for this connector instance.                 |     |
| Connector Name   | connector.name            | `CONNECTOR_NAME`            |         | Yes       | Name of the connector.                                                    |     |
| Connector Scope  | connector.scope           | `CONNECTOR_SCOPE`           |         | Yes       | The scope or type of data the connector is importing (e.g., `Indicator`). |     |
| Log Level        | connector.log_level       | `CONNECTOR_LOG_LEVEL`       | info    | No        | Determines the verbosity of logs: `debug`, `info`, `warn`, or `error`.    |     |
| Polling Interval | connector.duration_period | `CONNECTOR_DURATION_PERIOD` | PT1H    | No        | ISO-8601 interval string (e.g., `PT5M`, `PT1H`) for the polling schedule. |     |

### Connector extra parameters environment variables
| Parameter               | config.yml          | Docker environment variable     | Default                | Mandatory | Description                                                                                   |
| ----------------------- | ------------------- | ------------------------------- | ---------------------- | --------- | --------------------------------------------------------------------------------------------- |
| API Base URL              | flare.api_base_url  | `FLARE_API_BASE_URL`            | api.flare.co | Yes       | Flare API base URL|
| API Key                 | flare.api_key       | `FLARE_API_KEY`                 |                        | Yes       | Flare API key                                                                                 |
| Tenant Id               | flare.tenant_id     | `FLARE_TENANT_ID`               | (default tenant)       | No        | The tenant in Flare for which the feed should be ingested.                                    |
| Event types             | flare.event_types   | `FLARE_EVENT_TYPES`             | stealer_log,domain,ransomleak,leak                  | No        | https://api.docs.flare.io/event-types/overview (supported types are stealer_log, domain, ransomleak and leak (leaked credentials))                                               |
| Event actions           | flare.event_actions | `FLARE_EVENT_ACTIONS`           | (all)                  | No        | Which event state (action) to filter by. Available actions are `ignored` and `remediated` |
| Historical polling days | flare.lookback_days | `FLARE_HISTORICAL_POLLING_DAYS` | 30                     | No        | Days of data to fetch on first run.                                                           |
| TLP Level               | flare.tlp_level     | `FLARE_TLP_LEVEL`               | clear                  | No        | TLP marking for created STIX objects.                                                         |

## Deployment
### Docker Deployment
1. Ensure `pycti` version in `requirements.txt` matches your OpenCTI version (e.g., `pycti==6.8.10`).
2. Build Docker image:
```bash
docker build -t opencti/connector-flare:rolling .
```
3. Register connector in the **main** OpenCTI `docker-compose.yml`:
```yaml
  connector-flare:
  image: opencti/connector-flare:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=Flare
      - CONNECTOR_SCOPE=Incident,Observable,Indicator
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - FLARE_API_BASE_URL=api.flare.io
      - FLARE_API_KEY=fw_xxxxxx
      - FLARE_TENANT_ID=changeme
      - FLARE_EVENT_TYPES=changeme
      - FLARE_EVENT_ACTIONS=changeme
      - FLARE_LOOKBACK_DAYS=30
      - FLARE_TLP_LEVEL=white
    restart: always
```
4. Start the connector:
```bash
docker compose up -d
```
> 🔁 Do not use the local `docker-compose.yml`. Always integrate the connector in OpenCTI’s main `docker-compose.yml`.

### Manual Deployment
1. Copy and configure `config.yml` from the provided `config.yml.sample`
2. Install dependencies:
```bash
pip3 install -r requirements.txt
```
3. Start the connector:
```bash
python3 src/connector.py
```

## Usage
The connector runs automatically at the interval set by `duration_period`. You can also manually trigger it from:

**OpenCTI → Data Management → Ingestion → Connectors**

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.
