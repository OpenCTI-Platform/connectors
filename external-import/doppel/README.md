# OpenCTI Doppel Connector

The Doppel connector integrates OpenCTI with the Doppel Threat Intelligence platform by ingesting alerts as STIX 2.1
Observables.

| Status            | Date       | Comment |
|-------------------|------------|---------|
| Filigran Verified | 2025-08-18 | -       |

## Table of Contents

- [OpenCTI Doppel Connector](#opencti-doppel-connector)
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
    - [Behavior](#behavior)
    - [Debugging](#debugging)
    - [Additional information](#additional-information)

## Introduction

This connector fetches alerts from the Doppel API and imports them into OpenCTI as Observables. Each alert is mapped to a
STIX 2.1 Observable object, enriched with metadata such as severity, entity state, platform, audit logs, etc.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- Doppel API access (URL + API Key + User API Key (optional) + Organization Code (optional))

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in
`config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter        | config.yml      | Docker environment variable | Default | Mandatory | Description                                                               |
|------------------|-----------------|-----------------------------|---------|-----------|---------------------------------------------------------------------------|
| Connector ID     | id              | `CONNECTOR_ID`              |         | Yes       | A unique `UUIDv4` identifier for this connector instance.                 |
| Connector Name   | name            | `CONNECTOR_NAME`            |         | Yes       | Name of the connector.                                                    |
| Connector Scope  | scope           | `CONNECTOR_SCOPE`           |         | Yes       | The scope or type of data the connector is importing (e.g., `Indicator`). |
| Log Level        | log_level       | `CONNECTOR_LOG_LEVEL`       | info    | No        | Determines the verbosity of logs: `debug`, `info`, `warn`, or `error`.    |
| Polling Interval | duration_period | `CONNECTOR_DURATION_PERIOD` | PT1H    | Yes       | ISO-8601 interval string (e.g., `PT5M`, `PT1H`) for the polling schedule. |                                                   |

### Connector extra parameters environment variables

| Parameter               | config.yml                     | Docker environment variable      | Role |  Default | Mandatory | Description                           |
|-------------------------|--------------------------------|----------------------------------|---------|---------|-----------|---------------------------------------|
| API base URL            | doppel.api_base_url            | `DOPPEL_API_BASE_URL`            |    Connectivity: Defines the network entry point for all API requests.      | https://api.doppel.com/v1        | Yes       | Doppel API base URL                   |
| API key                 | doppel.api_key                 | `DOPPEL_API_KEY`                 |    Authentication: Provides the primary security credentials for service access.      |         | Yes       | Doppel API key                        |
| User API key                 | doppel.user_api_key       | `DOPPEL_USER_API_KEY`            |     Authorization: Used for user-specific identity.     |         | No        | Doppel User API key                   |
| Organization Code       | doppel.organization_code       | `DOPPEL_ORGANIZATION_CODE`       |     Scope: Identifies the specific organizational workspace for multi-tenant keys.     |         | No        | Organization Code for Doppel API Keys |
| Alerts endpoint         | doppel.alerts_endpoint         | `DOPPEL_ALERTS_ENDPOINT`         |     Routing: Specifies the API resource path for alert ingestion.     | /alerts | Yes       | API endpoint for fetching alerts      |
| Historical polling days | doppel.historical_polling_days | `DOPPEL_HISTORICAL_POLLING_DAYS` |     Synchronization: Determines the time-window for initial data fetching.     | 30      | No        | Days of data to fetch on first run    |
| Max retries             | doppel.max_retries             | `DOPPEL_MAX_RETRIES`             |     Resilience: Configures automated error recovery from transient failures.     | 3       | No        | Retry attempts on API errors          |
| Retry delay (seconds)   | doppel.retry_delay             | `DOPPEL_RETRY_DELAY`             |     Rate Management: Controls the frequency of requests during error recovery.     | 30      | No        | Delay between retry attempts          |
| TLP Level               | doppel.tlp_level               | `DOPPEL_TLP_LEVEL`               |     Data Governance: Assigns sensitivity markings for downstream sharing.     | clear   | No        | TLP marking for created STIX objects. |
| Page size               | doppel.page_size               | `DOPPEL_PAGE_SIZE`               |    Performance: Optimizes request volume and memory usage per fetch.      | 100                       | No        | Number of alerts to fetch per request |

## Deployment

### Docker Deployment

1. Ensure `pycti` version in `requirements.txt` matches your OpenCTI version (e.g., `pycti==6.9.0`).

2. Build Docker image:

```bash
docker build -t opencti/connector-doppel:latest .
```

3. Register connector in the **main** OpenCTI `docker-compose.yml`:

```yaml
  connector-doppel:
    image: opencti/connector-doppel:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=changeme
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=Doppel Threat Intelligence
      - CONNECTOR_SCOPE=Indicator
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - DOPPEL_API_BASE_URL=https://api.doppel.com
      - DOPPEL_API_KEY=changeme
      - DOPPEL_USER_API_KEY=changeme
      - DOPPEL_ORGANIZATION_CODE=changeme
      - DOPPEL_ALERTS_ENDPOINT=/v1/alerts
      - DOPPEL_HISTORICAL_POLLING_DAYS=30
      - DOPPEL_MAX_RETRIES=3
      - DOPPEL_RETRY_DELAY=30
      - DOPPEL_TLP_LEVEL=clear
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
python3 main.py
```

## Usage

The connector runs automatically at the interval set by `duration_period`. You can also manually trigger it from:

**OpenCTI → Data Management → Ingestion → Connectors**

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

- Fetches alerts from Doppel API paginated by `last_activity_timestamp`
- Converts each alert into a STIX 2.1 Observable object
- Bundles and sends the STIX objects to OpenCTI
- Includes platform, score, brand, audit logs, notes, etc. as `custom_properties`
- On first run, fetches up to `HISTORICAL_POLLING_DAYS`; subsequent runs are delta-based

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:

- API call details and retry behavior
- Alert count fetched per run
- STIX conversion trace per alert
- Connector and bundle send status

You can also use:

```python
self.helper.connector_logger.debug("message")
```

...for custom log messages.

## Additional information

- This connector strictly follows OpenCTI's standard STIX schema.
- Custom properties like `x_opencti_brand`, `x_opencti_source` are preserved.
- When queue_state is actioned/taken_down, Observables are converted to STIX 2.1 Indicators.
- Supports safe reprocessing with unique `indicator_id` generation to avoid duplication.