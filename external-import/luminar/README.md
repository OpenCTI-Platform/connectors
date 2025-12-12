# OpenCTI Luminar CTI Connector

Table of Contents

- [OpenCTI Luminar CTI Connector](#opencti-luminar-cti-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Luminar CTI Connector extra parameters environment variables](#luminar-cti-connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)


## Introduction

Cognyte is a global leader in security analytics software that empowers governments and
enterprises with Actionable Intelligence for a safer world. Our open software fuses, analyzes
and visualizes disparate data sets at scale to help security organizations find the needles in the
haystacks. Over 1,000 government and enterprise customers in more than 100 countries rely on
Cognyte’s solutions to accelerate security investigations and connect the dots to successfully
identify, neutralize, and prevent threats to national security, business continuity and cyber
security.
Luminar is an asset-based cybersecurity intelligence platform that empowers enterprise
organizations to build and maintain a proactive threat intelligence operation that enables to
anticipate and mitigate cyber threats, reduce risk, and enhance security resilience. Luminar
enables security teams to define a customized, dynamic monitoring plan to uncover malicious
activity in its earliest stages on all layers of the Web.

This integration connects with the [Luminar Threat Intelligence](https://www.cognyte.com/) TAXII version 2 server.
It includes the following feeds:

| Feeds | Alias |
|--------:|:-----------------------|
|     ioc | IOCs                   |
|  leakedrecords | Leaked Records  |
|      cyberfeeds | Cyber Feeds    |

## Installation

### Requirements

- OpenCTI Platform >= 6.7.4

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter         | config.yml      | Docker environment variable | Default         | Mandatory | Description                                                                                 |
|-------------------|-----------------|-----------------------------|-----------------|-----------|---------------------------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                   |
| Connector Type    | type            | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                               |
| Connector Name    | name            | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                      |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.    |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD` | PT1D            | No        | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT30M`. |

### Luminar CTI Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                  | config.yml                 | Docker environment variable                 | Default | Mandatory | Description                                                                                                   |
|----------------------------|----------------------------|---------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------------------------------|
| Luminar Base URL    | base_url                   | `LUMINAR_BASE_URL`                   | https://www.cyberluminar.com       | Yes       | Luminar Base URL                                                                                       |
| Luminar Account ID    | account_id                   | `LUMINAR_ACCOUNT_ID`                   | /       | Yes       | Luminar Account ID                                                                                      |
| Luminar Client ID     | client_id                   | `LUMINAR_CLIENT_ID`               | /       | Yes       | Luminar Client ID                                                                           |
| Luminar Client Secret        | client_secret                   | `LUMINAR_CLIENT_SECRET`                  | /       | Yes       | Luminar Client Secret                                                                               |
| Inititla Fetch Date                  | initial_fetch_date                  | `LUMINAR_INITIAL_FETCH_DATE`           | YYYY-MM-DD   | Yes       | Fetch feeds from date (ex: 2025-01-01) |
| Create Observable| create_observable | `LUMINAR_CREATE_OBSERVABLE` | True    | Yes       | Whether to create observables in OpenCTI Platform.                       |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.4.0`. If you don't, it will take the latest version, but
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

Then, start the connector from luminar/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

The connector pulls feeds from Luminar and ingests into platform.


## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.
