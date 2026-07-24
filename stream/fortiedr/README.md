# OpenCTI FortiEDR Connector

The FortiEDR connector is a **stream** connector that synchronises IP indicators
of compromise (IOCs) curated in OpenCTI to a [FortiEDR](https://www.fortinet.com/products/endpoint-security/fortiedr)
IP Set in real time. It listens to an OpenCTI live stream and keeps a managed
FortiEDR IP Set in sync so endpoint policies can act on known-bad infrastructure.

Table of Contents

- [OpenCTI FortiEDR Connector](#opencti-fortiedr-connector)
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
  - [Supported observables and TAXII alternative](#supported-observables-and-taxii-alternative)

## Introduction

[FortiEDR](https://www.fortinet.com/products/endpoint-security/fortiedr) is
Fortinet's endpoint detection and response solution. Its Central Manager exposes
a REST API that, among other things, manages IP Sets. This connector uses that
API to keep an IP Set continuously synchronised with the IP indicators curated in
OpenCTI.

## Requirements

- OpenCTI Platform >= 7.260722.0
- A reachable FortiEDR Central Manager
- A FortiEDR user with the REST API role enabled (the user must have logged in
  once to set its password)

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
| Connector Name  | `name`                      | `CONNECTOR_NAME`                      | `FortiEDR` | No        | Name of the connector.                                   |
| Connector Scope | `scope`                     | `CONNECTOR_SCOPE`                     | `fortiedr` | No        | The scope of the connector.                              |
| Log Level       | `log_level`                 | `CONNECTOR_LOG_LEVEL`                 | `error`    | No        | Logs verbosity (`debug`, `info`, `warn`, `warning`, `error`). |
| Live Stream ID  | `live_stream_id`            | `CONNECTOR_LIVE_STREAM_ID`            | /          | Yes       | ID of the live stream created in the OpenCTI UI.         |
| Listen Delete   | `live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`     | No        | Whether to listen to delete events on the live stream.  |
| No Dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true` | No        | Whether to ignore dependencies when processing events.  |

### Connector extra parameters environment variables

| Parameter    | config.yml     | Docker environment variable | Default   | Mandatory | Description                                                       |
| ------------ | -------------- | --------------------------- | --------- | --------- | ---------------------------------------------------------------- |
| API base URL | `api_base_url` | `FORTIEDR_API_BASE_URL`     | /         | Yes       | Base URL of the FortiEDR Central Manager.                        |
| Organization | `organization` | `FORTIEDR_ORGANIZATION`     | /         | No        | Organization name (required on multi-tenant consoles).          |
| Username     | `username`     | `FORTIEDR_USERNAME`         | /         | Yes       | FortiEDR REST API user name.                                     |
| Password     | `password`     | `FORTIEDR_PASSWORD`         | /         | Yes       | FortiEDR REST API user password.                                 |
| IP Set name  | `ip_set_name`  | `FORTIEDR_IP_SET_NAME`      | `OpenCTI` | No        | Name of the managed IP Set (created automatically if missing).  |
| SSL verify   | `ssl_verify`   | `FORTIEDR_SSL_VERIFY`       | `true`    | No        | Whether to verify the SSL certificate of the Central Manager.   |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-fortiedr:rolling
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Copy `config.yml.sample` to `src/config.yml` and fill in the values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

- On indicator **create**/**update**: if the indicator is an IPv4/IPv6 address, it
  is added to the managed FortiEDR IP Set (the set is created if it does not exist).
- On indicator **delete**: the IP is removed from the managed IP Set.

## Supported observables and TAXII alternative

The FortiEDR REST API exposes IP Sets, so this connector synchronises IPv4 and
IPv6 indicators only.

For full IOC coverage (file hashes, domains, URLs), FortiEDR provides a native
STIX/TAXII Threat Intelligence Feed integration. Point a FortiEDR Threat
Intelligence Feed connector at OpenCTI's built-in TAXII server to ingest those
indicator types directly.
