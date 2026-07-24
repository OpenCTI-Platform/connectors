# OpenCTI CTM360 ThreatCover Connector

The CTM360 ThreatCover connector is an **external-import** connector that imports curated
threat intelligence from the CTM360 ThreatCover module into OpenCTI.

ThreatCover exposes its indicators and observables through a **TAXII 2.1** collection. The
connector polls that collection on a schedule (incrementally, using the TAXII `added_after`
filter and connector state), imports the returned STIX 2.1 objects, attributes them to a
CTM360 ThreatCover author identity and applies a configurable TLP marking.

It complements the existing CTM360 CyberBlindSpot, Cyna and HackerView connectors (which
cover the CyberBlindspot REST modules); ThreatCover is a distinct, TAXII-native feed. The
generic OpenCTI TAXII2 connector can also consume this feed - this dedicated connector
provides a preset, branded ThreatCover integration.

Table of Contents

- [OpenCTI CTM360 ThreatCover Connector](#opencti-ctm360-threatcover-connector)
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

[CTM360 ThreatCover](https://www.ctm360.com/) is CTM360's Threat Intelligence Platform
module. It distributes curated indicators/observables over TAXII 2.1 (and STIX exports).
This connector consumes the TAXII "Observables" collection and imports it into OpenCTI.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260722.0
- A CTM360 ThreatCover TAXII 2.1 endpoint, API token and collection id
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

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
| --------------- | ---------- | --------------------------- | --------------- | --------- | ---------------------------------------------------------------------------------------- |
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name  | name       | `CONNECTOR_NAME`            | CTM360 ThreatCover | No        | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | error           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

This connector follows the same TAXII model as the generic OpenCTI `taxii2` connector
(server discovery + token / API-key / basic authentication).

| Parameter       | config.yml      | Docker environment variable          | Default     | Mandatory | Description                                                                  |
| --------------- | --------------- | ------------------------------------ | ----------- | --------- | --------------------------------------------------------------------------- |
| Discovery URL   | discovery_url   | `CTM360_THREATCOVER_DISCOVERY_URL`   |             | Yes       | CTM360 ThreatCover TAXII discovery URL (tenant specific).                   |
| Collection      | collection      | `CTM360_THREATCOVER_COLLECTION`      |             | Yes       | TAXII collection to poll (the ThreatCover "Observables" collection id/title).|
| TAXII 2.1       | v21             | `CTM360_THREATCOVER_V21`             | `true`      | No        | Use TAXII 2.1 (set false for a TAXII 2.0 server).                           |
| Use token       | use_token       | `CTM360_THREATCOVER_USE_TOKEN`       | `true`      | No        | Authenticate with a token (Authorization header).                          |
| Token           | token           | `CTM360_THREATCOVER_TOKEN`           |             | No        | CTM360 ThreatCover API token (used when `use_token` is true).              |
| Use API key     | use_apikey      | `CTM360_THREATCOVER_USE_APIKEY`      | `false`     | No        | Authenticate with a custom API-key header instead of a token.              |
| API-key header  | apikey_key      | `CTM360_THREATCOVER_APIKEY_KEY`      |             | No        | Header name to use when `use_apikey` is true.                              |
| API-key value   | apikey_value    | `CTM360_THREATCOVER_APIKEY_VALUE`    |             | No        | Header value to use when `use_apikey` is true.                            |
| Username        | username        | `CTM360_THREATCOVER_USERNAME`        |             | No        | Username for HTTP basic auth (when neither token nor API key is used).      |
| Password        | password        | `CTM360_THREATCOVER_PASSWORD`        |             | No        | Password for HTTP basic auth.                                              |
| Cert path       | cert_path       | `CTM360_THREATCOVER_CERT_PATH`       |             | No        | Optional client certificate path for mutual TLS.                          |
| Verify SSL      | verify_ssl      | `CTM360_THREATCOVER_VERIFY_SSL`      | `true`      | No        | Whether to verify the TAXII server TLS certificate.                        |
| TLP level       | tlp_level       | `CTM360_THREATCOVER_TLP_LEVEL`       | `amber`     | No        | Default TLP marking applied to imported entities.                          |
| Duration period | duration_period | `CONNECTOR_DURATION_PERIOD`          | `PT1H`      | No        | ISO-8601 interval between two polls.                                        |

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
your environment.

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

1. Reads the last `added_after` timestamp from its state (empty on the first run).
2. Discovers the TAXII server from `discovery_url` (using the configured token / API-key /
   basic authentication), resolves the configured `collection` (by id or title), and polls
   it with the `added_after` filter, following TAXII pagination (`more` / `next`) until all
   pages are retrieved - the same TAXII handling as the generic OpenCTI `taxii2` connector.
3. Passes the returned STIX 2.1 objects through, applying the configured TLP marking and
   attributing SDOs to the CTM360 ThreatCover author identity (SCOs keep their native
   form; marking-definition / identity / relationship objects are passed untouched).
4. Bundles the objects (plus the author identity and TLP marking) and sends them to
   OpenCTI, then records the run timestamp as the next `added_after`.

OpenCTI deduplicates STIX objects by their deterministic ids across runs.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
