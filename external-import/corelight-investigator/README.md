# OpenCTI Corelight Investigator Connector

The Corelight Investigator connector is an **external-import** connector that pulls alerts
and detections from Corelight Investigator (Corelight's SaaS NDR) into OpenCTI as STIX
Incidents.

On a schedule it queries the Investigator "Detections and Alerts" API, maps each alert /
detection to a STIX Incident (with the normalized Investigator severity 1-10 mapped to the
OpenCTI severity), extracts the source / destination IP observables referenced by an alert
and relates them to the Incident, and attributes everything to a Corelight Investigator
author identity with a configurable TLP marking. Imports are incremental via connector
state.

Table of Contents

- [OpenCTI Corelight Investigator Connector](#opencti-corelight-investigator-connector)
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

[Corelight Investigator](https://corelight.com/products/investigator) is Corelight's
SaaS NDR platform. It produces ML / behavioral / signature / threat-intel alerts and
detections mapped to MITRE ATT&CK. This connector imports those findings into OpenCTI.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260710.0
- A Corelight Investigator API key (read access to Detections and Alerts)
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml      | Docker environment variable | Default                 | Mandatory | Description                                                                              |
| --------------- | --------------- | --------------------------- | ----------------------- | --------- | ---------------------------------------------------------------------------------------- |
| Connector ID    | id              | `CONNECTOR_ID`              | /                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type            | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT         | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name  | name            | `CONNECTOR_NAME`            | Corelight Investigator  | No        | Name of the connector.                                                                   |
| Connector Scope | scope           | `CONNECTOR_SCOPE`           | corelight-investigator  | No        | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | PT1H                    | No        | Interval in ISO-8601 format between two runs of the connector.                           |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter          | config.yml         | Docker environment variable             | Default          | Mandatory | Description                                                                  |
| ------------------ | ------------------ | --------------------------------------- | ---------------- | --------- | --------------------------------------------------------------------------- |
| API base URL       | api_base_url       | `CORELIGHT_INVESTIGATOR_API_BASE_URL`   |                  | Yes       | Corelight Investigator API base URL (region specific).                      |
| API key            | api_key            | `CORELIGHT_INVESTIGATOR_API_KEY`        |                  | Yes       | Corelight Investigator API key (Authorization bearer header).               |
| Alerts path        | alerts_path        | `CORELIGHT_INVESTIGATOR_ALERTS_PATH`    | `/api/v1/alerts` | No        | Path of the Detections and Alerts API endpoint.                             |
| Import window days | import_window_days | `CORELIGHT_INVESTIGATOR_IMPORT_WINDOW_DAYS` | `7`          | No        | Look-back window (days) used on the first run.                              |
| Max alerts         | max_alerts         | `CORELIGHT_INVESTIGATOR_MAX_ALERTS`     | `1000`           | No        | Maximum number of alerts to request per run.                                |
| TLP level          | tlp_level          | `CORELIGHT_INVESTIGATOR_TLP_LEVEL`      | `amber`          | No        | Default TLP marking applied to imported entities.                           |
| Verify SSL         | ssl_verify         | `CORELIGHT_INVESTIGATOR_SSL_VERIFY`     | `true`           | No        | Whether to verify the API server TLS certificate.                           |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==7.260701.0`. If you don't, it will take the latest version, but
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

Then, start the connector from `src` directory:

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

On each run the connector:

1. Determines the lookback start time (`last_run` from state, or now minus
   `import_window_days` on the first run).
2. Queries the Investigator Detections and Alerts API for alerts since that time.
3. Maps each alert / detection to a STIX Incident; the normalized Investigator severity
   (1-10) is mapped to the OpenCTI severity:

   | Investigator severity | OpenCTI severity |
   | --------------------- | ---------------- |
   | 9-10                  | critical         |
   | 7-8                   | high             |
   | 4-6                   | medium           |
   | 1-3                   | low              |

4. Extracts the source / destination IP observables referenced by an alert and creates
   `related-to` relationships from the Incident to those observables.
5. Bundles the Incidents, observables, author identity and TLP marking and sends them to
   OpenCTI, then records the run timestamp.

The exact REST path/parameters of the Investigator API are documented in the in-product
API reference; the endpoint path is configurable via `alerts_path` if your tenant differs.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
