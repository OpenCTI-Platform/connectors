# OpenCTI Import ATT&CK Navigator TTPs


Table of Contents

- [OpenCTI Import ATT&CK Navigator TTPs](#opencti-internal-import-yara-connector)
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

This connector ingests techniques defined in an ATT&CK Navigator layer file, converting them as Attack Patterns.
The ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) is a tool used to visualize and annotate different tactics and techniques from the MITRE ATT&CK framework. 
A "layer file" is a file format that represents saved visualizations (layers) of selected techniques within the Navigator tool.

When importing a layer file from ATT&CK Navigator, you have the option to associate the imported techniques with an existing entity in the platform. Here are the types of relationships that can be established based on the selected entity:

- **Threats**: If the entity is an intrusion set, a threat actor (either individual or group), a malware, or a campaign, the techniques will be linked to the selected entity using a "uses" relationship. This indicates that the techniques are employed by the entity in pursuit of its objectives.
- **Security Platform**: If the selected entity is a Security Platform, the techniques will be linked to the entity using a "should-cover" relationship. This suggests that the security platform is expected to cover or mitigate these techniques as part of its functional capabilities.
- **No Entity Selected**: If no entity is selected, the techniques will be imported globally.

### Supported formats

The connector only supports JSON files exported from the ATT&CK Navigator tool. 
Be sure to download files with the .json extension so that they are taken into account by the connector.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.15

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

| Parameter       | config.yml | Docker environment variable | Default                 | Mandatory | Description                                                                                                                                             |
|-----------------|------------|-----------------------------|-------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                               |
| Connector Name  | name       | `CONNECTOR_NAME`            | ImportTTPsFileNavigator | Yes       | Name of the connector.                                                                                                                                  |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | application/json        | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. <br/>This connector support only "application/json" file type. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | error                   | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                  |


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.8.15`. If you don't, it will take the latest version, but
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
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

The connector uses the “plyara” library to parse and extract YARA rules.