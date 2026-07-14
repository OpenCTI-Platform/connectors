# OpenCTI Trellix TIE Connector

The Trellix TIE connector is a **stream** connector that pushes OpenCTI file-hash
indicators to Trellix Threat Intelligence Exchange (TIE) as enterprise file reputations,
over the OpenDXL fabric.

On each indicator `create` / `update` carrying a STIX file-hash pattern, it sets the TIE
reputation (a configurable trust level, default `KNOWN_MALICIOUS`) for the MD5 / SHA-1 /
SHA-256 hashes via the OpenDXL TIE client, so Trellix endpoint security acts on the
intelligence.

This is the standard mechanism for integrating threat intelligence with the McAfee/Trellix
ecosystem (Trellix EDR has no outbound IOC REST API), and the same approach used by other
threat intelligence platforms.

Table of Contents

- [OpenCTI Trellix TIE Connector](#opencti-trellix-tie-connector)
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

[Trellix Threat Intelligence Exchange (TIE)](https://www.trellix.com/) shares file
reputations across the Trellix ecosystem over the Data Exchange Layer (DXL). This
connector publishes OpenCTI file-hash indicators to TIE as enterprise reputations using
the OpenDXL TIE client.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260710.0
- A DXL broker and an ePO-provisioned OpenDXL client configuration (`dxlclient.config`
  with the broker list and client certificate), authorized to publish to the
  `TIE Server Set Enterprise Reputation` topic
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk) library matching your OpenCTI version

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

| Parameter                             | config.yml                  | Docker environment variable             | Default         | Mandatory | Description                                                                                                                                            |
| ------------------------------------- | --------------------------- | --------------------------------------- | --------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Connector ID                          | id                          | `CONNECTOR_ID`                          | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                              |
| Connector Type                        | type                        | `CONNECTOR_TYPE`                        | STREAM          | Yes       | Should always be set to `STREAM` for this connector.                                                                                                   |
| Connector Name                        | name                        | `CONNECTOR_NAME`                        | Trellix TIE     | No        | Name of the connector.                                                                                                                                 |
| Connector Scope                       | scope                       | `CONNECTOR_SCOPE`                       | trellix-tie     | No        | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                               |
| Log Level                             | log_level                   | `CONNECTOR_LOG_LEVEL`                   | error           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                 |
| Connector Live Stream ID              | live_stream_id              | `CONNECTOR_LIVE_STREAM_ID`              | live            | No        | ID of the live stream created in the OpenCTI UI                                                                                                        |
| Connector Live Stream Listen Delete   | live_stream_listen_delete   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | true            | No        | Listen to all delete events concerning the entity, depending on the filter set for the OpenCTI stream.                                                 |
| Connector Live Stream No dependencies | live_stream_no_dependencies | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | true            | No        | Always set to `True` unless you are synchronizing 2 OpenCTI platforms and you want to get an entity and all context (relationships and related entity) |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter       | config.yml      | Docker environment variable     | Default           | Mandatory | Description                                                                          |
| --------------- | --------------- | ------------------------------- | ----------------- | --------- | ----------------------------------------------------------------------------------- |
| DXL config path | dxl_config_path | `TRELLIX_TIE_DXL_CONFIG_PATH`   |                   | Yes       | Path to the ePO-provisioned OpenDXL config file (`dxlclient.config`), mounted in.    |
| Trust level     | trust_level     | `TRELLIX_TIE_TRUST_LEVEL`       | `KNOWN_MALICIOUS` | No        | TIE trust level to set: `KNOWN_MALICIOUS`, `MOST_LIKELY_MALICIOUS`, `MIGHT_BE_MALICIOUS`, `UNKNOWN`, `MIGHT_BE_TRUSTED`, `MOST_LIKELY_TRUSTED`, `KNOWN_TRUSTED`, `KNOWN_TRUSTED_INSTALLER`, `NOT_SET`. |
| Comment         | comment         | `TRELLIX_TIE_COMMENT`           | `Set by OpenCTI`  | No        | Comment attached to the reputation set in TIE.                                       |

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

This is a stream connector: once deployed it continuously listens to the configured OpenCTI live stream and pushes file-hash indicator events to Trellix TIE in real time, so it requires no scheduled run or manual interaction.

The live stream it consumes is set by `CONNECTOR_LIVE_STREAM_ID` (the id of a live stream created under `Data management` -> `Data sharing` -> `Live streams` in the OpenCTI platform). Make sure that stream is started and that its filters include the indicators you want to publish to TIE.

## Behavior

The connector listens to the configured OpenCTI live stream. For each `create` / `update`
event on an `indicator`:

1. It parses the STIX pattern for file hashes (`file:hashes.'SHA-256'`, `MD5`, `SHA-1`).
2. If at least one hash is present, it connects to the DXL fabric (lazily, on first use)
   and calls the OpenDXL TIE client `set_file_reputation` with the configured trust level,
   the resolved hashes (MD5 / SHA-1 / SHA-256), the indicator name as filename, and the
   configured comment.
3. Indicators without a file hash, and `delete` events, are ignored (TIE reputations are
   not removed by this connector).

Notes:

- Only file/cert hashes are supported - TIE reputations do not cover domains, URLs or IPs.
- The DXL connection is established lazily and reused across events.

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
