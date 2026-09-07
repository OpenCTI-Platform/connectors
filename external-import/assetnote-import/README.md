# OpenCTI AssetNote External Import Connector

This connector ingests both Assets and Exposures from the Assetnote platform into OpenCTI.

On each run, the connector will utilise Assetnote's GraphQL API to retrieve any Assets and Exposures updated since its last run. Objects are converted as follows
- **Assets:** `Infrastructure` Object
- **Exposures:** `Incident Response` Object encompassing a: `Vulnerability`, `Course of Action`, `Note(s)` (for each Interaction), `Infrastructure` (for the affected Asset) and, optionally, a `Software` object. 

`Incident Response` Objects can be linked to an OpenCTI status template reflecting the state of the Exposure in the AssetNote Platform (Unresolved, Triaged, Resolved or Ignored)

Table of Contents

- [OpenCTI AssetNote External Import Connector](#opencti-assetnote-external-import-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
    - [Setting up Incident Response status templates](#setting-up-incident-response-status-templates)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

## Installation

### Requirements

- Python >= 3.12
- OpenCTI Platform >= 7.260722.0
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
| Connector Name  | name       | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                    | config.yml                    | Docker environment variable                    | Default | Mandatory | Description                                                                                                                    |
| ---------------------------- | ------------------------------ | ----------------------------------------------- | ------- | --------- | -------------------------------------------------------------------------------------------------------------------------------- |
| API base URL                 | api_base_url                   | `ASSETNOTE_IMPORT_API_BASE_URL`                 |         | Yes       | Base URL of the Assetnote platform to query.                                                                                      |
| API key                      | api_key                        | `ASSETNOTE_IMPORT_API_KEY`                      |         | Yes       | Assetnote API key used to authenticate requests.                                                                                  |
| Unresolved status name       | unresolved_status_name          | `ASSETNOTE_IMPORT_UNRESOLVED_STATUS_NAME`       |         | No        | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote UNRESOLVED exposures.                             |
| Triaged status name          | triaged_status_name             | `ASSETNOTE_IMPORT_TRIAGED_STATUS_NAME`          |         | No        | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote TRIAGED exposures.                                |
| Resolved status name         | resolved_status_name            | `ASSETNOTE_IMPORT_RESOLVED_STATUS_NAME`         |         | No        | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote RESOLVED exposures.                               |
| Ignored status name          | ignored_status_name             | `ASSETNOTE_IMPORT_IGNORED_STATUS_NAME`          |         | No        | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote IGNORED exposures.                                |
| First run retrieval datetime | first_run_retrieval_datetime    | `ASSETNOTE_IMPORT_FIRST_RUN_RETRIEVAL_DATETIME` | epoch   | No        | ISO 8601 datetime to retrieve assets/exposures from on the connector's first run, before any state is stored. Ignored afterwards. |

### Setting up Incident Response status templates

Each of the `*_status_name` variables are optional, but if they are to be set the following must be undertaken:
1. In OpenCTI go to `Settings` -> `Customization` -> `Entity types`.
2. Select `Incident Response`, then open its `Workflow` tab.
3. Click the pencil icon to open the workflow panel, then click `+` to add a status.
4. Create a new status by pressing the `+` icon, providing a name and colour. 
5. Repeat for each state you want to track (Unresolved, Triaged, Resolved, Ignored).
6. Use the exact template name you chose for each one as the corresponding `*_status_name` config values in the connector.

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-assetnote-import:latest
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

<!--
Describe how the connector functions:
* What data is ingested, updated, or modified
* Important considerations for users when utilizing this connector
* Additional relevant details
-->

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
