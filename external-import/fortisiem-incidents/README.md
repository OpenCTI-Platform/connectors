# OpenCTI FortiSIEM Incidents Connector

The FortiSIEM Incidents connector is an **external-import** connector that pulls
incidents from FortiSIEM into OpenCTI as STIX Incidents. It is the import side of
a bidirectional integration: pair it with the `stream/fortisiem` connector (which
pushes IOCs to FortiSIEM Watch Lists) to send IOCs out and bring incidents in.

Table of Contents

- [OpenCTI FortiSIEM Incidents Connector](#opencti-fortisiem-incidents-connector)
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

## Introduction

FortiSIEM is Fortinet's SIEM platform. This connector periodically queries the
FortiSIEM REST API for incidents and imports them into OpenCTI as STIX 2.1
Incidents, attributed to a FortiSIEM author identity and marked with a
configurable TLP, with related network observables.

## Requirements

- OpenCTI Platform >= 7.260715.0
- A reachable FortiSIEM Supervisor with the REST API enabled
- A FortiSIEM REST API user

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

| Parameter         | config.yml        | Docker environment variable   | Default               | Mandatory | Description                                          |
| ----------------- | ----------------- | ----------------------------- | --------------------- | --------- | --------------------------------------------------- |
| Connector ID      | `id`              | `CONNECTOR_ID`                | /                     | Yes       | A unique `UUIDv4` identifier for this connector.     |
| Connector Name    | `name`            | `CONNECTOR_NAME`              | `FortiSIEM Incidents` | No        | Name of the connector.                              |
| Connector Scope   | `scope`           | `CONNECTOR_SCOPE`            | `fortisiem`           | No        | The scope of the connector.                         |
| Log Level         | `log_level`       | `CONNECTOR_LOG_LEVEL`        | `error`               | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).  |
| Duration Period   | `duration_period` | `CONNECTOR_DURATION_PERIOD`  | `PT15M`               | No        | ISO-8601 period between two runs.                   |

### Connector extra parameters environment variables

| Parameter          | config.yml           | Docker environment variable           | Default | Mandatory | Description                                          |
| ------------------ | -------------------- | ------------------------------------- | ------- | --------- | --------------------------------------------------- |
| API base URL       | `api_base_url`       | `FORTISIEM_INCIDENTS_API_BASE_URL`    | /       | Yes       | Base URL of the FortiSIEM Supervisor.              |
| Organization       | `organization`       | `FORTISIEM_INCIDENTS_ORGANIZATION`    | `super` | No        | Organization used to scope the REST API user.      |
| Username           | `username`           | `FORTISIEM_INCIDENTS_USERNAME`        | /       | Yes       | FortiSIEM REST API user name.                      |
| Password           | `password`           | `FORTISIEM_INCIDENTS_PASSWORD`        | /       | Yes       | FortiSIEM REST API user password.                 |
| Import window days | `import_window_days` | `FORTISIEM_INCIDENTS_IMPORT_WINDOW_DAYS` | `7`  | No        | Days of incidents to import on the first run.      |
| TLP level          | `tlp_level`          | `FORTISIEM_INCIDENTS_TLP_LEVEL`       | `amber` | No        | TLP marking applied to imported incidents.         |
| SSL verify         | `ssl_verify`         | `FORTISIEM_INCIDENTS_SSL_VERIFY`      | `true`  | No        | Whether to verify the SSL certificate.             |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-fortisiem-incidents:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file from `config.yml.sample` (at the connector root) and fill in the values, then:

```shell
pip install -r src/requirements.txt
python src/main.py
```

## Behavior

On each run the connector fetches FortiSIEM incidents updated since the last run
(or within the configured import window on the first run), converts each incident
to a STIX Incident, extracts network observables (source/destination IP,
hostnames) and relates them to the incident, then sends the bundle to OpenCTI.
