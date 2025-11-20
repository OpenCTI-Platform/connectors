# OpenCTI External Ingestion Connector Aerospace SPARTA

Table of Contents

* [OpenCTI External Ingestion Connector Cofense ThreatHQ](#opencti-external-ingestion-connector-aerospace-sparta)
  * [Introduction](#introduction)
  * [Configuration variables](#configuration-variables-environment)
    * [OpenCTI environment variables](#opencti-environment-variables)
    * [Base connector environment variables](#base-connector-environment-variables)
    * [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  * [Deployment](#deployment)
    * [Docker Deployment](#docker-deployment)
    * [Manual Deployment](#manual-deployment)
  * [Usage](#usage)
  * [Behavior](#behavior)
  * [Debugging](#debugging)
  * [Additional information](#additional-information)

## Status Filigran

| Status            | Date       | Comment |
|-------------------|------------|---------|
| Filigran Verified | 2025-11-07 | -       |

## Introduction

The Aerospace Corporation created the Space Attack Research and Tactic Analysis (SPARTA) matrix to address the information and communication barriers that hinder the identification and sharing of space-system Tactic, Techniques, and Procedures (TTP).

SPARTA is intended to provide unclassified information to space professionals about how spacecraft may be compromised via cyber and traditional counterspace means. The matrix defines and categorizes commonly identified activities that contribute to spacecraft compromises. Where applicable the SPARTA TTPs are cross referenced to other Aerospace related work like TOR 2021-01333 REV A and TOR-2023-02161 Rev A which is available in the Related Work menu of the SPARTA website.

## Configuration variables environment

A variety of configuration options are available, and the connector will load them from a single source, following a specific order of precedence:

1. The `.env` file – This is the primary configuration source, if present. You can use the provided `.env.sample` as a reference.
2. The `config.yml` file – If no `.env` file is found, the connector will look for a `config.yml` file instead (a `config.yml.sample` is also available as a starting point).
3. System environment variables – If neither a `.env` nor a `config.yml` file is available, the connector will fall back to system environment variables.

A `docker-compose.yml` file is also available to simplify Docker-based deployments and supports passing environment variables through directly via the system environment.

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.8.6`. If you don't, it will take the latest version, but
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

Then, start the connector from sparta/src:

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

Scope:

* Attack Pattern
* Course of Action
* Indicator
* Identity

## Debugging

The connector can be debugged by setting the appropiate log level.
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
