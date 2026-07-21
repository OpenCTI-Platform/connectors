# OpenCTI DomainTools Feeds Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | -          | -       |

## Table of Contents

- [OpenCTI DomainTools Feeds Connector](#opencti-domaintools-feeds-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [DomainTools extra parameters environment variables](#domaintools-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector fetches data from DomainTools Threat Feeds (via the Real-time Feed API) and imports it into OpenCTI as Observables. Each feed entry is mapped to a Structured Threat Information Expression (STIX) 2.1 Observable object, enriched with metadata such as severity, entity state, platform, audit logs, etc. Created objects carry a Traffic Light Protocol (TLP) marking for downstream sharing.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- DomainTools API access (API Key + Other)

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
| Connector Scope | `scope`                | `CONNECTOR_SCOPE`           | stix2  | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | `log_level`            | `CONNECTOR_LOG_LEVEL`       | error   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period | `duration_period`      | `CONNECTOR_DURATION_PERIOD` | PT1H    | Yes       | The period of time between two connector runs (ISO 8601 duration format).                |

### DomainTools extra parameters environment variables

| Parameter               | config.yml                     | Docker environment variable      | Role | Default | Mandatory | Description                           |
|-------------------------|--------------------------------|----------------------------------|---------|---------|-----------|---------------------------------------|
| API base URL            | domaintools.api_base_url            | `DOMAINTOOLS_API_BASE_URL`            |    Connectivity: Defines the network entry point for all API requests.      | https://api.domaintools.com        | Yes       | DomainTools API base URL                   |
| API key                 | domaintools.api_key                 | `DOMAINTOOLS_API_KEY`                 |    Authentication: Provides the primary security credentials for service access.      |         | Yes       | DomainTools API key                        |
| Feed Type               | domaintools.feed_type         | `DOMAINTOOLS_FEED_TYPE`         |     Routing: Specifies the type of feed to ingest.     | nod      | Yes       | Type of feed to ingest (domainhotlist, domainrisk, nod, nad, noh, domaindiscovery)      |
| Session ID              | domaintools.session_id       | `DOMAINTOOLS_SESSION_ID`            |     Scope: Identifies the specific session for feed access.     |         | No        | A unique identifier for the session, used for resuming data retrieval from the last point. |
| TLP Level               | domaintools.tlp_level               | `DOMAINTOOLS_TLP_LEVEL`               |     Data Governance: Assigns sensitivity markings for downstream sharing.     | clear   | No        | TLP marking for created STIX objects. |
| After (minutes)         | domaintools.after       | `DOMAINTOOLS_AFTER`            |     Synchronization: Determines the time-window for data fetching.     |         | No        | The start of the query window (inclusive).   |
| Before (minutes)        | domaintools.before       | `DOMAINTOOLS_BEFORE`            |     Synchronization: Determines the time-window for data fetching.     |         | No        | The end of the query window (inclusive).   |
| Domain Filter           | domaintools.domain       | `DOMAINTOOLS_DOMAIN`            |     Filtering: Limits results to specific domains.     |         | No        | Filter for an exact domain or a domain substring by prefixing or suffixing your string with *. |
| From Beginning          | domaintools.frombeginning       | `DOMAINTOOLS_FROMBEGINNING`            |     Synchronization: Determines if fetching starts from the beginning.     |         | No        | When used with a new session ID, returns the first hour of data in the time window (rather than the last). |
| Top Results             | domaintools.top       | `DOMAINTOOLS_TOP`            |     Performance: Limits the number of results returned.     |         | No        | Limits the number of results in the response payload.    |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==6.5.1`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

Register connector in the **main** OpenCTI `docker-compose.yml`:

```yaml
  connector-domaintools:
    image: opencti/connector-domaintools:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=changeme
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=DomainTools Feeds
      - CONNECTOR_SCOPE=stix2
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT5M
      - DOMAINTOOLS_API_BASE_URL=https://api.domaintools.com
      - DOMAINTOOLS_API_KEY=changeme
      - DOMAINTOOLS_FEED_TYPE=nod
      - DOMAINTOOLS_SESSION_ID=OpenCTI-NOD
      - DOMAINTOOLS_TLP_LEVEL=clear
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

However, if you would like to force an immediate download of a new batch of data, navigate to:

**Data management → Ingestion → Connectors** in the OpenCTI platform.

Find the "DomainTools Feeds" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

- Fetches data from DomainTools Feeds paginated by `session_id`
- Converts each feed entry into a STIX 2.1 Observable object
- Bundles and sends the STIX objects to OpenCTI
- Includes platform, score, brand, audit logs, notes, etc. as `custom_properties`

## Debugging

The connector can be debugged by setting the appropriate log level. Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, for example, `self.helper.connector_logger.error("An error message")`.

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. Log output includes:

- API call details and retry behavior
- Data count fetched per run
- Page-by-page fetch progress
- STIX conversion trace per entry
- Bundle send status

## Additional information

- This connector strictly follows OpenCTI's standard STIX schema.
- Custom properties like `x_opencti_brand`, `x_opencti_source` are preserved.
- When queue_state is actioned/taken_down, Observables are converted to STIX 2.1 Indicators.
- Supports safe reprocessing with unique `indicator_id` generation to avoid duplication.