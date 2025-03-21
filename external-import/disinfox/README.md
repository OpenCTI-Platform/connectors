# OpenCTI External Ingestion Connector DISINFOX

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

Table of Contents

- [OpenCTI External Ingestion Connector DISINFOX](#opencti-external-ingestion-connector-disinfox)
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

## Installation

### Requirements

- OpenCTI Platform >= 6...
- A reacheable [DISINFOX](https://github.com/CyberDataLab/disinfox) API.
- A DISINFOX API Key. 

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` or  `.env` (duplicating the `example.env`) in Docker.

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter    | config.yml   | Docker environment variable | Default | Mandatory | Description |
|--------------|--------------|-----------------------------|---------|-----------|-------------|
| DISINFOX API base URL |  |  DISINFOX_URL                           |         | Yes       |     URL of a reachable DISINFOX installation        |
| DISINFOX API key      |       |  DISINFOX_API_KEY                           |         | Yes       |    The API key for DISINFOX, available in the user's Profile section         |

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

Make sure to:

- **Duplicate the `example.env` file**
- Rename it to `.env`.
- Adapt it to your instalation environment.

You can also directly edit the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`.

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

...

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` in `duration_period`.

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
This connector retrieves data from a DISINFOX instance.
It fetches STIX2 Bundles from the DISINFOX Public API to get newly added disinformation incidents to DISINFOX.

**It's essential** to get a DISINFOX API Key from the Profile page at DISINFOX.

## Debugging

The connector can be debugged by setting the appropiate log level.
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
