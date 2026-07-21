# OpenCTI FortiSIEM Connector

The FortiSIEM connector is a **stream** connector that synchronises indicators of
compromise (IOCs) curated in OpenCTI to a FortiSIEM Watch List in real time. It
listens to an OpenCTI live stream and adds IOC values as Watch List entries
through the FortiSIEM REST API, so rules and analytics can match events against
your trusted threat intelligence.

Table of Contents

- [OpenCTI FortiSIEM Connector](#opencti-fortisiem-connector)
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

FortiSIEM is Fortinet's security information and event management (SIEM)
platform. Watch Lists are dynamic groups of values used by rules and analytics.
This connector keeps a Watch List synchronised with the IOCs curated in OpenCTI
using the FortiSIEM REST API (`/phoenix/rest/watchlist/addTo`).

## Requirements

- OpenCTI Platform >= 7.260715.0
- A reachable FortiSIEM Supervisor with the REST API enabled
- A FortiSIEM REST API user
- The numeric ID of the target Watch List

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

| Parameter       | config.yml                  | Docker environment variable           | Default     | Mandatory | Description                                               |
| --------------- | --------------------------- | ------------------------------------- | ----------- | --------- | -------------------------------------------------------- |
| Connector ID    | `id`                        | `CONNECTOR_ID`                        | /           | Yes       | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name  | `name`                      | `CONNECTOR_NAME`                      | `FortiSIEM` | No        | Name of the connector.                                   |
| Connector Scope | `scope`                     | `CONNECTOR_SCOPE`                     | `fortisiem` | No        | The scope of the connector.                              |
| Log Level       | `log_level`                 | `CONNECTOR_LOG_LEVEL`                 | `error`     | No        | Logs verbosity (`debug`, `info`, `warn`, `warning`, `error`). |
| Live Stream ID  | `live_stream_id`            | `CONNECTOR_LIVE_STREAM_ID`            | /           | Yes       | ID of the live stream created in the OpenCTI UI.         |
| Listen Delete   | `live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`      | No        | Whether to listen to delete events on the live stream.  |
| No Dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true`  | No        | Whether to ignore dependencies when processing events.  |

### Connector extra parameters environment variables

| Parameter     | config.yml      | Docker environment variable | Default | Mandatory | Description                                                  |
| ------------- | --------------- | --------------------------- | ------- | --------- | ----------------------------------------------------------- |
| API base URL  | `api_base_url`  | `FORTISIEM_API_BASE_URL`    | /       | Yes       | Base URL of the FortiSIEM Supervisor.                      |
| Organization  | `organization`  | `FORTISIEM_ORGANIZATION`    | `super` | No        | Organization used to scope the REST API user.             |
| Username      | `username`      | `FORTISIEM_USERNAME`        | /       | Yes       | FortiSIEM REST API user name.                             |
| Password      | `password`      | `FORTISIEM_PASSWORD`        | /       | Yes       | FortiSIEM REST API user password.                        |
| Watch List ID | `watchlist_id`  | `FORTISIEM_WATCHLIST_ID`    | /       | Yes       | Numeric ID of the target Watch List.                     |
| Entry age-out | `entry_age_out` | `FORTISIEM_ENTRY_AGE_OUT`   | `30d`   | No        | Age-out applied to Watch List entries.                   |
| SSL verify    | `ssl_verify`    | `FORTISIEM_SSL_VERIFY`      | `true`  | No        | Whether to verify the SSL certificate of the Supervisor. |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-fortisiem:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `src/config.yml` file based on the provided `config.yml.sample` and fill in the values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

- On indicator **create**/**update**: the IOC value is added to the configured
  Watch List with the configured age-out.
- On indicator **delete**: Watch List entries expire automatically through their
  age-out, so no explicit delete is performed.

## Supported observables

The connector extracts the value of the following single-observable STIX patterns
and adds it to the Watch List: IPv4 addresses, IPv6 addresses, domain names, URLs
and file hashes (MD5, SHA-1, SHA-256). For large-scale threat feed ingestion,
FortiSIEM also provides a native threat feed framework.
