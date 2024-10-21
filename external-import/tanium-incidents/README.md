# OpenCTI Tanium Incidents Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

Table of Contents

- [OpenCTI Tanium Incidents Connector](#opencti-tanium-incidents-connector)
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

This connector allows organizations to feed OpenCTI Sightings using **Tanium Alerts** knowledge.

This connector leverages OpenCTI connector *scheduler*, so it imports Tanium alerts and create corresponding sightings
in OpenCTI at a defined periodicity.

![Import workflow overview](doc/workflow.png "Import workflow overview")

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0
- Tanium Threat Response >= 3.X.X

### Configuration

| Parameter                            | Docker envvar                        | Mandatory | Description                                                                             |
|--------------------------------------|--------------------------------------|-----------|-----------------------------------------------------------------------------------------|
| `tanium_incidents_url`               | `TANIUM_INCIDENTS_URL`               | Yes       | The Tanium instance API URL.                                                            |
| `tanium_incidents_url_console`       | `TANIUM_INCIDENTS_URL_CONSOLE`       | Yes       | The Tanium instance console URL.                                                        |
| `tanium_incidents_ssl_verify`        | `TANIUM_INCIDENTS_SSL_VERIFY`        | Yes       | Enable the SSL certificate check (default: `true`)                                      |
| `tanium_incidents_token`             | `TANIUM_INCIDENTS_TOKEN`             | Yes       | The Tanium login user.                                                                  |
| `tanium_incidents_import_alerts`     | `TANIUM_INCIDENTS_IMPORT_ALERTS`     | No        | Enable alerts import                                                                    |
| `tanium_incidents_import_start_date` | `TANIUM_INCIDENTS_IMPORT_START_DATE` | No        | Import starting date (in YYYY-MM-DD format) - used only if connector's state is not set |

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

| Parameter                 | config.yml                | Docker environment variable | Default         | Mandatory | Description                                                                              |
|---------------------------|---------------------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID              | id                        | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type            | type                      | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name            | name                      | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope           | scope                     | `CONNECTOR_SCOPE`           | tanium          | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level                 | log_level                 | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Duration Period | connector_duration_period | `CONNECTOR_DURATION_PERIOD` | /               | Yes       | Interval duration between connector launches (must be in ISO 8601 format)                |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter               | config.yml                         | Docker environment variable          | Default | Mandatory | Description                                                                             |
|-------------------------|------------------------------------|--------------------------------------|---------|-----------|-----------------------------------------------------------------------------------------|
| Tanium API base URL     | tanium_incidents_url               | `TANIUM_INCIDENTS_URL`               |         | Yes       | The Tanium instance API URL.                                                            |
| Tanium Console base URL | tanium_incidents_url_console       | `TANIUM_INCIDENTS_URL_CONSOLE`       |         | Yes       | The Tanium instance console URL.                                                        |
| SSL verification        | tanium_incidents_ssl_verify        | `TANIUM_INCIDENTS_SSL_VERIFY`        | True    | Yes       | Enable the SSL certificate check                                                        |
| Tanium API token        | tanium_incidents_token             | `TANIUM_INCIDENTS_TOKEN`             |         | Yes       | The Tanium login user.                                                                  |
| Alerts import           | tanium_incidents_import_alerts     | `TANIUM_INCIDENTS_IMPORT_ALERTS`     | True    | No        | Enable alerts import                                                                    |
| Import start date       | tanium_incidents_import_start_date | `TANIUM_INCIDENTS_IMPORT_START_DATE` |         | No        | Import starting date (in YYYY-MM-DD format) - used only if connector's state is not set |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
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

After Installation, the connector should require minimal interaction to use, and should update automatically at a
regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

<!--
Describe how the connector functions:
* What data is ingested, updated, or modified
* Important considerations for users when utilizing this connector
* Additional relevant details
-->

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.e.,
`self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->