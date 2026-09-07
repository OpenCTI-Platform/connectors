
# OpenCTI SOCRadar Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

## Table of Contents

- [OpenCTI SOCRadar Connector](#opencti-socradar-connector)
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

OpenCTI connector for importing threat intelligence feeds from SOCRadar platform.

This connector imports threat intelligence data from SOCRadar into OpenCTI. It processes various types of indicators including:

- IP addresses (IPv4 and IPv6)
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)

## Installation

### Requirements

- OpenCTI Platform >= 6...

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

⚠️ Please be aware that `CONNECTOR_DURATION_PERIOD` default value takes precedence over `RADAR_RUN_INTERVAL` default value if none of them are set.

The `RADAR_FEED_LISTS` parameter should contain the name/id pairs of the feed lists to fetch on SOCRadar.
Example using `config.yml`:

```yaml
feed_lists:
  feed_list_1: "ID_1"
  feed_list_2: "ID_2"
```

Example using env vars:

```bash
RADAR_FEED_LISTS='{"feed_list_1":"ID_1","feed_list_2":"ID_2"}'
```

<br>

> **(Deprecated)**
>
> The `RADAR_COLLECTIONS_UUID` parameter should contain the collection IDs you want to fetch from SOCRadar.
>
> Example using `config.yml`:
>
> ```yaml
> radar_collections_uuid:
>   collection_1:
>     id: ["COLLECTION_ID"]
>     name: ["COLLECTION_NAME"]
>   collection_2:
>     id: ["COLLECTION_ID"]
>     name: ["COLLECTION_NAME"]
> ```
>
> Example using env vars:
>
> ```bash
> RADAR_COLLECTIONS_UUID='{"collection_1":{"id":["COLLECTION_ID"],"name":["COLLECTION_NAME"]},"collection_2":{"id":["COLLECTION_ID"],"name":["COLLECTION_NAME"]}}'
> ```

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.6.18`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t opencti/connector-socradar:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment and to establish network with OpenCTI. Then, start the docker container with the provided `docker-compose.yml`.

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

Then, start the connector:

```shell
python3 src/main.py
```
