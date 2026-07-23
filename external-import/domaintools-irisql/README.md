# OpenCTI DomainTools IrisQL Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | -          | -       |

## Table of Contents

- [OpenCTI DomainTools IrisQL Connector](#opencti-domaintools-irisql-connector)
  - [Table of Contents](#table-of-contents)
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

This connector uses IrisQL to fetch data from DomainTools Iris Investigate and import it into OpenCTI. It maps each query result to a STIX 2.1 Observable, enriching it with context like IP addresses, name servers, mail servers, email addresses, etc. To ensure secure data handling, all created objects are assigned a Traffic Light Protocol (TLP) marking for downstream sharing.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- DomainTools API credential

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

| Parameter               | config.yml                     | Docker environment variable       | Default | Mandatory | Description                           |
|-------------------------|--------------------------------|----------------------------------|---------|-----------|---------------------------------------|
| API base URL            | domaintools.api_base_url            | `DOMAINTOOLS_API_BASE_URL`            |  | https://api.domaintools.com/v1/iris-investigate/       | Yes       | DomainTools API base URL                   |
| API key                 | domaintools.api_key                 | `DOMAINTOOLS_API_KEY`                 |      | Yes       | DomainTools API key                        |
| IrisQL Query            | domaintools.iris_ql         | `DOMAINTOOLS_IRIS_QL`         |             | Yes       | IrisQL query to execute                        |
| STORE IRIS DATA | domaintools.store_iris_data | `DOMAINTOOLS_STORE_IRIS_DATA` | false |No| Store DomainTools Iris data as note object. |
| TLP Level               | domaintools.tlp_level               | `DOMAINTOOLS_TLP_LEVEL`                  | clear   | No        | TLP marking for created STIX objects. |

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
      - CONNECTOR_NAME=DomainTools IrisQL
      - CONNECTOR_SCOPE=stix2
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT5M
      - DOMAINTOOLS_API_BASE_URL=https://api.domaintools.com/v1/iris-investigate/
      - DOMAINTOOLS_API_KEY=changeme
      - DOMAINTOOLS_IRIS_QL="# IrisQL-1.0\ndomain contains \"sso\"\nAND\nfirst_seen within \"the last 3 hour\"\nAND\nrisk_score greater_than_or_equal \"90\""
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

Find the "DomainTools IrisQL" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

- Converts each query result into a STIX 2.1 Observable object
- Bundles and sends the STIX objects to OpenCTI

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
