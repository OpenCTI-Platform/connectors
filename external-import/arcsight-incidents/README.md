# OpenCTI ArcSight Incidents Connector

The ArcSight Incidents connector is an **external-import** connector that pulls
cases and their security events from ArcSight ESM into OpenCTI. It is the import
side of a bidirectional integration: pair it with the `stream/arcsight` connector
(which pushes IOCs to ESM Active Lists) to send IOCs out and bring cases in.

ArcSight exposes two distinct concepts that map to two STIX entities:

- **Security events** (detections/alerts) referenced by a case are modeled as
  STIX **Incidents**.
- The **case** itself (a case-management artifact) is modeled as a STIX
  **Case-Incident** that references the event Incidents it groups through its
  `object_refs`.

Table of Contents

- [OpenCTI ArcSight Incidents Connector](#opencti-arcsight-incidents-connector)
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

ArcSight ESM (OpenText) is a SIEM platform. This connector periodically queries
the ESM Service Layer REST API (`CaseService` and `SecurityEventService`) for
cases and the events they reference, then imports them into OpenCTI as STIX 2.1
Case-Incidents (the cases) and Incidents (the events), attributed to an ArcSight
author identity and marked with a configurable TLP.

## Requirements

- OpenCTI Platform >= 7.260710.0
- A reachable ArcSight ESM Manager (Service Layer REST API enabled)
- An ESM account allowed to read cases

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

| Parameter       | config.yml        | Docker environment variable  | Default              | Mandatory | Description                                          |
| --------------- | ----------------- | ---------------------------- | -------------------- | --------- | --------------------------------------------------- |
| Connector ID    | `id`              | `CONNECTOR_ID`               | /                    | Yes       | A unique `UUIDv4` identifier for this connector.     |
| Connector Name  | `name`            | `CONNECTOR_NAME`             | `ArcSight Incidents` | No        | Name of the connector.                              |
| Connector Scope | `scope`           | `CONNECTOR_SCOPE`            | /                    | Yes       | The scope of the connector.                         |
| Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`        | `error`              | No        | Logs verbosity (`debug`, `info`, `warn`, `warning`, `error`). |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD`  | `PT15M`              | No        | ISO-8601 period between two runs.                   |

### Connector extra parameters environment variables

| Parameter    | config.yml     | Docker environment variable        | Default | Mandatory | Description                                       |
| ------------ | -------------- | ---------------------------------- | ------- | --------- | ------------------------------------------------- |
| API base URL | `api_base_url` | `ARCSIGHT_INCIDENTS_API_BASE_URL`  | /       | Yes       | Base URL of the ArcSight ESM Manager.            |
| Username     | `username`     | `ARCSIGHT_INCIDENTS_USERNAME`      | /       | Yes       | ESM user name.                                   |
| Password     | `password`     | `ARCSIGHT_INCIDENTS_PASSWORD`      | /       | Yes       | ESM user password.                               |
| Max cases    | `max_cases`    | `ARCSIGHT_INCIDENTS_MAX_CASES`     | `200`   | No        | Maximum number of cases to fetch per run.        |
| TLP level    | `tlp_level`    | `ARCSIGHT_INCIDENTS_TLP_LEVEL`     | `amber` | No        | TLP marking applied to imported incidents.       |
| SSL verify   | `ssl_verify`   | `ARCSIGHT_INCIDENTS_SSL_VERIFY`    | `true`  | No        | Whether to verify the SSL certificate.           |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-arcsight-incidents:latest
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

On each run the connector authenticates against the ESM `LoginService`, lists case
ids via `CaseService` (capped at `max_cases`) and fetches each case. For every case
it also resolves the referenced security events via `SecurityEventService`, converts
each event to a STIX Incident, and converts the case to a STIX Case-Incident that
references those Incidents through its `object_refs`. The resulting bundle is sent
to OpenCTI, which deduplicates both entity types by their deterministic id across
runs.
