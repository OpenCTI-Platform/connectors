# OpenCTI Doppel Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | -          | -       |

## Table of Contents

- [OpenCTI Doppel Connector](#opencti-doppel-connector)
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
    - [Mapping to OpenCTI entities](#mapping-to-opencti-entities)
    - [Entity type detection](#entity-type-detection)
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

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

Below are the parameters you'll need to set for OpenCTI:

### OpenCTI environment variables

| Parameter     | config.yml `opencti` | Docker environment variable | Default | Mandatory | Description                                          |
|---------------|----------------------|-----------------------------|---------|-----------|------------------------------------------------------|
| OpenCTI URL   | `url`                | `OPENCTI_URL`               | /       | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`              | `OPENCTI_TOKEN`             | /       | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml `connector` | Docker environment variable | Default | Mandatory | Description                                                                              |
|-----------------|------------------------|-----------------------------|---------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | `id`                   | `CONNECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Name  | `name`                 | `CONNECTOR_NAME`            | /       | Yes       | Name of the connector.                                                                   |
| Connector Scope | `scope`                | `CONNECTOR_SCOPE`           | doppel  | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | `log_level`            | `CONNECTOR_LOG_LEVEL`       | info    | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period | `duration_period`      | `CONNECTOR_DURATION_PERIOD` | PT1H    | Yes       | The period of time between two connector runs (ISO 8601 duration format).                |

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

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==6.5.1`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

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

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`.

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for your environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

After installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of alerts, navigate to:

**Data management → Ingestion → Connectors** in the OpenCTI platform.

Find the "Doppel" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

- Fetches alerts from Doppel API paginated by `last_activity_timestamp`
- Converts each alert into a STIX 2.1 Observable object
- Bundles and sends the STIX objects to OpenCTI
- Includes platform, score, brand, audit logs, notes, etc. as `custom_properties`
- On first run, fetches up to `HISTORICAL_POLLING_DAYS`; subsequent runs are delta-based

## Debugging

The connector can be debugged by setting the appropriate log level. Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. Log output includes:

- API call details and retry behavior
- Alert count fetched per run
- Page-by-page fetch progress
- STIX conversion trace per alert
- Bundle send status

## Additional information

- This connector strictly follows OpenCTI's standard STIX schema.
- Custom properties like `x_opencti_brand`, `x_opencti_source` are preserved.
- When queue_state is actioned/taken_down, Observables are converted to STIX 2.1 Indicators.
- Supports safe reprocessing with unique `indicator_id` generation to avoid duplication.
