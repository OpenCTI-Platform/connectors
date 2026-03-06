# OpenCTI TeamT5 External Import Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

A connector enabling the automatic ingestion of Reports and Indicator Bundles from the Team T5 Platform to an OpenCTI Instance.

## Table of Contents

- [OpenCTI TeamT5 External Import Connector](#opencti-teamt5-external-import-connector)
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

The TeamT5 External Import Connector enables automatic Ingestion of Threat Intelligence from the TeamT5 Platform into an OpenCTI Instance, doing so through the retrieval of Reports and Indicator Bundles.

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Python 3.10+
- Access to TeamT5 API (API key required)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Description                                          |
|---------------|------------|-----------------------------|------------------------------------------------------|
| OpenCTI URL   | opencti.url        | `OPENCTI_URL`               | The URL to your OpenCTI Platform.                     |
| OpenCTI Token | opencti.token      | `OPENCTI_TOKEN`             | The API Token for the Connector to use in your OpenCTI Platform |

### Base connector environment variables

| Parameter            | config.yml           | Docker environment variable     | Default         | Description                                                                              |
|----------------------|---------------------|---------------------------------|-----------------|------------------------------------------------------------------------------------------|
| Connector ID         | connector.id        | `CONNECTOR_ID`                  |                | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Name       | connector.name      | `CONNECTOR_NAME`                | TeamT5 External Import Connector | Name of the connector.                                                                   |
| Connector Scope      | connector.scope     | `CONNECTOR_SCOPE`               |                 | The scope applied to the connector. |
| Log Level            | connector.log_level | `CONNECTOR_LOG_LEVEL`           | info            | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period      | connector.duration_period | `CONNECTOR_DURATION_PERIOD`   | P1D            | Interval for the scheduler process in ISO-8601 format (e.g., P1D for 1 day).        |

### Connector extra parameters environment variables

| Parameter    | config.yml         | Docker environment variable | Default | Description                                                                                      |
|--------------|-------------------|-----------------------------|---------|--------------------------------------------------------------------------------------------------|
| API base URL | teamt5.api_base_url | `TEAMT5_API_BASE_URL`   |         | The base URL for the TeamT5 API.                                                                 |
| API key      | teamt5.api_key      | `TEAMT5_API_KEY`        |         | **Deprecated.** Pre-obtained Bearer token. Use `client_id`/`client_secret` instead.             |
| Client ID    | teamt5.client_id    | `TEAMT5_CLIENT_ID`      |         | OAuth 2.0 client ID. Requires `client_secret` to also be set.                                   |
| Client Secret | teamt5.client_secret | `TEAMT5_CLIENT_SECRET` |         | OAuth 2.0 client secret. Requires `client_id` to also be set.                                   |
| TLP Level    | teamt5.tlp_level    | `TEAMT5_TLP_LEVEL`      | clear   | TLP marking for ingested data. Options: clear, white, green, amber, amber+strict, red.           |
| First Run Retrieval Timestamp | teamt5.first_run_retrieval_timestamp | `TEAMT5_FIRST_RUN_RETRIEVAL_TIMESTAMP` |         | Unix timestamp (integer). On the connector's first run, Reports and Indicator Bundles created after this timestamp will be retrieved. After this first run, the connector will automatically only retrieve the newest Reports and Indicator Bundles.|

### Authentication

The recommended authentication method is **OAuth 2.0 Client Credentials**:

```
TEAMT5_CLIENT_ID=<your-client-id>
TEAMT5_CLIENT_SECRET=<your-client-secret>
```

The connector will POST to `https://api.threatvision.org/oauth/token` on startup and automatically refresh the token before it expires.

> **Deprecated:** The static API key (`TEAMT5_API_KEY`) is still supported for backwards compatibility but should not be used for new deployments. When both `api_key` and OAuth credentials are provided, OAuth takes precedence.

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided docker-compose.yml

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

After installation, the connector should require minimal interaction to use, and will update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Import` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

The TeamT5 connector ingests two types of data from the TeamT5 platform:

- **Reports**: Fetches new threat intelligence reports, converting them to a STIX format and pushes them to your OpenCTI Instance. This results in the ingestion of all relevant objects, relationships and an External Reference to the PDF of the report for further viewing.

- **Indicator Bundles**: Fetches new Indicator Bundles and pushes them to your OpenCTI Instance.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

## Additional information

- It should be noted that all objects ingested by the connector will be marked with the TLP Level you define in its configuration.
- The connector stores the timestamps of the most recent Report and Indicator Bundle pushed into your OpenCTI Instance from Team T5. This means that, each time it runs, it will only retrieve and push any <i>new</i> Reports or Indicator Bundles.
