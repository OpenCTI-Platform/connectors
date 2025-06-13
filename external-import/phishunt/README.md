# Phishunt Connector

Table of Contents

- [OpenCTI External Ingestion Connector Template](#opencti-external-ingestion-connector-template)
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
    - [Debugging](#debugging)

## Status Filigran

| Status            | Date       | Comment |
|-------------------|------------|---------|
| Filigran Verified | 2025-06-13 | -       |

## Introduction

This connector retrieves urls of active websites that are suspicious of being phishing from the feed Phishunt

## Installation

### Requirements

- OpenCTI Platform >= 6.7.0

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                     |
|---------------|------------|-----------------------------|-----------|-------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The API token for authenticating with OpenCTI.  |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter        | config.yml       | Docker environment variable  | Default | Mandatory | Description                                                                                  |
|------------------|------------------|------------------------------|---------|-----------|----------------------------------------------------------------------------------------------|
| Connector ID     | id               | `CONNECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                    |
| Connector Name   | name             | `CONNECTOR_NAME`             |         | Yes       | Name of the connector.                                                                       |
| Connector Scope  | scope            | `CONNECTOR_SCOPE`            |         | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.     |
| Log Level        | log_level        | `CONNECTOR_LOG_LEVEL`        | error    | No       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.       |
| Duration Period  | duration_period  | `CONNECTOR_DURATION_PERIOD`  |      | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT30M`.  |
| ~~Interval~~ ⚠️Deprecated | ~~/~~             | ~~`PHISHUNT_INTERVAL`~~   | ~~3~~       | ~~❌~~    | ~~In days, must be strictly greater than 1.~~ |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter            | config.yml              | Docker environment variable        | Default                    | Mandatory | Description                                                                                                   |
|----------------------|-------------------------|------------------------------------|----------------------------|-----------|---------------------------------------------------------------------------------------------------------------|
| API key              | api_key                 | `PHISHUNT_API_KEY`                 |                            | Yes       | The API key for Phishunt.                                                                                     |
| Create Indicators    | create_indicators       | `PHISHUNT_CREATE_INDICATORS`       | `True`                     | No        | If true then indicators will be created from Pulse indicators and added to the report.                        |
| OpenCTI Score        | default_x_opencti_score | `PHISHUNT_DEFAULT_X_OPENCTI_SCORE` | `40`                       | No        | The default x_opencti_score to use for indicators. If a per indicator type score is not set, this is used.    |
| OpenCTI Score IP     | x_opencti_score_ip      | `PHISHUNT_X_OPENCTI_SCORE_IP`      | `default_x_opencti_score`  | No        | The x_opencti_score to use for IP indicators. If not set, the default value is `default_x_opencti_score`.     |
| OpenCTI Score Domain | x_opencti_score_domain  | `PHISHUNT_X_OPENCTI_SCORE_DOMAIN`  | `default_x_opencti_score`  | No        | The x_opencti_score to use for Domain indicators. If not set, the default value is `default_x_opencti_score`. |
| OpenCTI Score URL    | x_opencti_score_url     | `PHISHUNT_X_OPENCTI_SCORE_URL`     | `default_x_opencti_score`  | No        | The x_opencti_score to use for URL indicators. If not set, the default value is `default_x_opencti_score`.    |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.6.13`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.
