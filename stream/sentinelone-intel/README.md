# OpenCTI SentinelOne Intel Stream Connector

The SentinelOne Intel Stream Connector is a standalone Python process that monitors the creation of STIX Indicators in OpenCTI and automatically creates them in a SentinelOne Instance. 

Table of Contents

- [OpenCTI SentinelOne Intel Stream Connector](#opencti-sentinelone-intel-stream-connector)
    - [Introduction](#introduction)
    - [Installation](#installation)
        - [Requirements](#requirements)
        - [SentinelOne Setup](#sentinelone-setup)
        - [OpenCTI Setup](#opencti-setup)
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

The SentinelOne Intel Stream Connector enables real-time synchronization of threat intelligence indicators from OpenCTI to SentinelOne's threat intelligence platform as Indicators of compromise. Upon the creation of Indicators within the OpenCTI platform, the connector automatically evaluates their STIX patterns and pushes compatible indicators to a SentinelOne Instance. 

SentinelOne supports the following Indicator of Compromise (IOC) types:
- **File Hashes**: SHA256, SHA1, MD5
- **Network Indicators**: URLs, Domain names, IPv4 addresses

As such, the connector supports Indicators with **single-element** patterns corresponding to the above STIX SCOs. 

## Installation

### Requirements

- **OpenCTI Platform** >= 6.7.11
- **Python** 3.x (for manual deployment)
- **SentinelOne** management console access with API permissions
- **Docker** (for Docker deployment)

### SentinelOne Setup

#### Generating an API Key

![Generating An API Token In S1](doc/api_generation.png)

- Click on your email address in the top right corner of the menu on the SentinelOne Console. 
- Click the `Actions` dropdown button and hover over `API Token Operations`.
- Click `Regenerate API token` and proceed with the required Authentication.
- **Note:** you do not need to include the `'APIToken '`component of the string in any configs

<br>

#### Determining Your SentinelOne URL
Your SentinelOne URL is simply the first component of the URL you use to access the console.

When configuring the connector, do not include the terminating `/`. For example, for the above image, you would input `https://mysentinelone.instance.net`



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

| Parameter                             | config.yml                  | Docker environment variable             | Default                            | Mandatory | Description                                                                                                                                            |
|---------------------------------------|-----------------------------|-----------------------------------------|------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID                          | id                          | `CONNECTOR_ID`                          | /                                  | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                              |
| Connector Type                        | type                        | `CONNECTOR_TYPE`                        | STREAM                             | Yes       | Should always be set to `STREAM` for this connector.                                                                                                   |
| Connector Name                        | name                        | `CONNECTOR_NAME`                        | SentinelOne Intel Stream Connector | Yes       | Name of the connector.                                                                                                                                 |
| Connector Scope                       | scope                       | `CONNECTOR_SCOPE`                       | all                                | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                               |
| Log Level                             | log_level                   | `CONNECTOR_LOG_LEVEL`                   | info                               | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                 |
| Connector Live Stream ID              | live_stream_id              | `CONNECTOR_LIVE_STREAM_ID`              | live                               | Yes       | ID of the live stream created in the OpenCTI UI                                                                                                        |
| Connector Live Stream Listen Delete   | live_stream_listen_delete   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | true                               | Yes       | Listen to all delete events concerning the entity, depending on the filter set for the OpenCTI stream.                                                 |
| Connector Live Stream No dependencies | live_stream_no_dependencies | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | true                               | Yes       | Always set to `True` unless you are synchronizing 2 OpenCTI platforms and you want to get an entity and all context (relationships and related entity) |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

> **Note:** At least one scope ID (Account, Site, or Group) must be configured. Account ID and Site ID cannot be used together.

| Parameter    | config.yml | Docker environment variable    | Mandatory | Description                                                                                      |
|--------------|------------|--------------------------------|-----------|--------------------------------------------------------------------------------------------------| 
| API URL      | url        | `SENTINELONE_INTEL_URL`        | Yes       | The base URL of your SentinelOne management console (e.g., https://your-console.sentinelone.net) |
| API Key      | api_key    | `SENTINELONE_INTEL_API_KEY`    | Yes       | SentinelOne API token for authentication                                                         |
| Account ID   | account_id | `SENTINELONE_INTEL_ACCOUNT_ID` | No        | SentinelOne Account ID for scoping indicators (at least one ID required)                         |
| Site ID      | site_id    | `SENTINELONE_INTEL_SITE_ID`    | No        | SentinelOne Site ID for scoping indicators (cannot be used with Account ID)                      |
| Group ID     | group_id   | `SENTINELONE_INTEL_GROUP_ID`   | No        | SentinelOne Group ID for scoping indicators                                                      |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-sentinelone-intel:latest
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

Then, start the connector from sentinelone-intel/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a
regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.


<br>

### Creating the Connector User
It is best practice to create a new user under the `Connectors` group and to use its token to interface with your instance.

![Generating A User In OpenCTI](doc/user_creation.png)

- Locate the gear (Settings) icon on the left menu and click `Security`.
- On the menu on the right click on the `Users` option. 
- Click the blue `+` icon at the bottom of the list
- Enter `[C] S1 Indicator Connector`. **Note:** you can name this whatever you'd like, but you should include `[C]` at the start regardless.
- Enter the required information and ensure that under the `Groups` field `Connectors` is this selected option. 

<br>

### Creating a Dedicated Stream

- To create a dedicated stream for this connector head to `Data sharing` -> `Live streams` in the OpenCTI platform.

![Creating a Stream in OpenCTI](doc/stream_creation.png)

- Provide the stream with a relevant name so that it can be easily identified. 
- Optional filters can be applied to determine which OpenCTI events the connector receivies. One should certainly set the following as to ensure that the stream only handles Indicators with STIX patterns
  - **Entity Type**: Set to `Indicator`
  - **Pattern Type**: Set to `stix`
- Further filters based on your needs (e.g., specific labels or creators)
- From here, the stream's ID can be utilised as the value of the `CONNECTOR_LIVE_STREAM_ID` variable.

<br>



## Behavior

The connector simply consumes the assigned stream, filtering for events where Indicators that use STIX patterns are found. The connector will determine if the Indicator's pattern is of a format SentinelOne can accept and will enact the required processing in order to push it to a SentinelOne instance as such. 

Based on the IOC types SentinelOne supports, the connector can only process Indicators from OpenCTI whose pattern references the following STIX Cyber Observable Objects (SCOs):
- **File Hashes**: SHA256, SHA1, MD5
- **Network Indicators**: URLs, Domain names, IPv4 addresses

Alongside this, the connector is only able to consume basic **single-expression** STIX patterns (e.g., file:hashes.'SHA-256' = '<hash>').

Compound patterns containing logical operators (AND, OR, FOLLOWEDBY, etc.) or multiple observables are **not supported** and will thus be ignored.


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.
