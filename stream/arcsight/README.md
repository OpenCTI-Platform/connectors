# OpenCTI ArcSight Connector

The ArcSight connector is a **stream** connector that synchronises indicators of
compromise (IOCs) curated in OpenCTI to an ArcSight ESM Active List in real time.
It listens to an OpenCTI live stream and adds/removes IOC values to a configurable
Active List through the ESM Service Layer REST API, so correlation rules can match
events against your trusted threat intelligence.

Table of Contents

- [OpenCTI ArcSight Connector](#opencti-arcsight-connector)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)
  - [Supported observables](#supported-observables)

## Introduction

ArcSight ESM (OpenText) is a security information and event management (SIEM)
platform. Active Lists are in-memory tables used by correlation rules. This
connector keeps an Active List synchronised with the IOCs curated in OpenCTI
using the ESM Service Layer REST API (`LoginService` for authentication and
`ActiveListService` for entry management).

## Requirements

- OpenCTI Platform >= 7.260722.0
- A reachable ArcSight ESM Manager (Service Layer REST API enabled)
- An ESM account allowed to read/write the target Active List
- The resource ID of the target Active List (with a column to store IOC values)

## Configuration variables

Configuration parameters can be provided in either `config.yml` (see
`config.yml.sample`), `docker-compose.yml` (environment variables) or directly as
environment variables.

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml                  | Docker environment variable           | Default    | Mandatory | Description                                               |
| --------------- | --------------------------- | ------------------------------------- | ---------- | --------- | -------------------------------------------------------- |
| Connector ID    | `id`                        | `CONNECTOR_ID`                        | /          | Yes       | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name  | `name`                      | `CONNECTOR_NAME`                      | `ArcSight` | No        | Name of the connector.                                   |
| Connector Scope | `scope`                     | `CONNECTOR_SCOPE`                     | `arcsight` | No        | The scope of the connector.                              |
| Log Level       | `log_level`                 | `CONNECTOR_LOG_LEVEL`                 | `error`    | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).       |
| Live Stream ID  | `live_stream_id`            | `CONNECTOR_LIVE_STREAM_ID`            | /          | Yes       | ID of the live stream created in the OpenCTI UI.         |
| Listen Delete   | `live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`     | No        | Whether to listen to delete events on the live stream.  |
| No Dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true` | No        | Whether to ignore dependencies when processing events.  |

### Connector extra parameters environment variables

| Parameter      | config.yml       | Docker environment variable | Default | Mandatory | Description                                                  |
| -------------- | ---------------- | --------------------------- | ------- | --------- | ----------------------------------------------------------- |
| API base URL   | `api_base_url`   | `ARCSIGHT_API_BASE_URL`     | /       | Yes       | Base URL of the ArcSight ESM Manager.                       |
| Username       | `username`       | `ARCSIGHT_USERNAME`         | /       | Yes       | ESM user name.                                              |
| Password       | `password`       | `ARCSIGHT_PASSWORD`         | /       | Yes       | ESM user password.                                          |
| Active List ID | `active_list_id` | `ARCSIGHT_ACTIVE_LIST_ID`   | /       | Yes       | Resource ID of the target Active List.                     |
| Value column   | `value_column`   | `ARCSIGHT_VALUE_COLUMN`     | `value` | No        | Active List column that stores the IOC value.              |
| SSL verify     | `ssl_verify`     | `ARCSIGHT_SSL_VERIFY`       | `true`  | No        | Whether to verify the SSL certificate of the ESM Manager.  |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-arcsight:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file at the connector root from `config.yml.sample` and fill in the values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

- On startup and on demand, the connector authenticates against the ESM
  `LoginService` to obtain an authentication token (re-issued automatically when
  it expires).
- On indicator **create**/**update**: the IOC value is added to the configured
  Active List (`ActiveListService/addEntries`).
- On indicator **delete**: the IOC value is removed
  (`ActiveListService/deleteEntries`).

## Supported observables

The connector extracts the value of the following single-observable STIX patterns
and writes it to the configured Active List column: IPv4 addresses, IPv6
addresses, domain names, URLs and file hashes (MD5, SHA-1, SHA-256).
