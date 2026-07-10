# OpenCTI Swimlane Connector

The Swimlane connector is an **external-import** connector that imports records
from a Swimlane application into OpenCTI as STIX **Case-Incidents**, so SOC cases
managed in Swimlane can be correlated and enriched with the threat intelligence
curated in OpenCTI.

Swimlane is a case-management (SOAR) platform, so its records are modeled as
OpenCTI Case-Incidents (a STIX Incident is reserved for alerts/detections).

Table of Contents

- [OpenCTI Swimlane Connector](#opencti-swimlane-connector)
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

Swimlane is a security orchestration, automation and response (SOAR) platform.
This connector periodically queries the Swimlane REST API for records in a
configured application and imports them into OpenCTI as STIX 2.1 Case-Incidents.
Field mapping is intentionally generic because Swimlane applications use custom
schemas; the record tracking id is used as the case name and the record id as an
external reference.

## Requirements

- OpenCTI Platform >= 7.260710.0
- A reachable Swimlane instance with the REST API enabled
- A Swimlane API token (Personal Access Token)
- The ID of the Swimlane application to import from

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

| Parameter       | config.yml        | Docker environment variable  | Default    | Mandatory | Description                                          |
| --------------- | ----------------- | ---------------------------- | ---------- | --------- | --------------------------------------------------- |
| Connector ID    | `id`              | `CONNECTOR_ID`               | /          | Yes       | A unique `UUIDv4` identifier for this connector.     |
| Connector Name  | `name`            | `CONNECTOR_NAME`             | `Swimlane` | No        | Name of the connector.                              |
| Connector Scope | `scope`           | `CONNECTOR_SCOPE`            | /          | Yes       | The scope of the connector.                         |
| Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`        | `error`    | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).  |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD`  | `PT15M`    | No        | ISO-8601 period between two runs.                   |

### Connector extra parameters environment variables

| Parameter      | config.yml       | Docker environment variable | Default | Mandatory | Description                                       |
| -------------- | ---------------- | --------------------------- | ------- | --------- | ------------------------------------------------- |
| API base URL   | `api_base_url`   | `SWIMLANE_API_BASE_URL`     | /       | Yes       | Base URL of the Swimlane instance.               |
| API token      | `api_token`      | `SWIMLANE_API_TOKEN`        | /       | Yes       | Swimlane API token (Personal Access Token).      |
| Application ID | `application_id` | `SWIMLANE_APPLICATION_ID`   | /       | Yes       | ID of the Swimlane application to import from.    |
| Max records    | `max_records`    | `SWIMLANE_MAX_RECORDS`      | `100`   | No        | Maximum number of records to fetch per run.      |
| TLP level      | `tlp_level`      | `SWIMLANE_TLP_LEVEL`        | `amber` | No        | TLP marking applied to imported case-incidents.  |
| SSL verify     | `ssl_verify`     | `SWIMLANE_SSL_VERIFY`       | `true`  | No        | Whether to verify the SSL certificate.           |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-swimlane:rolling
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `src/config.yml` file from the root `config.yml.sample` and fill in the values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

On each run the connector fetches records from the configured Swimlane application
(capped at `max_records`), converts each record to a STIX Case-Incident, and sends
the bundle to OpenCTI. OpenCTI deduplicates case-incidents by their deterministic
id across runs.
