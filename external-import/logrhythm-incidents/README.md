# OpenCTI LogRhythm Incidents Connector

The LogRhythm Incidents connector is an **external-import** connector that pulls
cases from LogRhythm SIEM into OpenCTI as STIX **Case-Incidents**. It is the import
side of a bidirectional integration: pair it with the existing `stream/logrhythm`
connector (which feeds LogRhythm lists from OpenCTI) to send IOCs out and bring
cases in.

LogRhythm cases are case-management artifacts, so they are modeled as OpenCTI
Case-Incidents (a STIX Incident is reserved for alarms/detections).

Table of Contents

- [OpenCTI LogRhythm Incidents Connector](#opencti-logrhythm-incidents-connector)
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

LogRhythm is a SIEM platform. This connector periodically queries the LogRhythm
Case API for cases and imports them into OpenCTI as STIX 2.1 Incidents, attributed
to a LogRhythm author identity and marked with a configurable TLP. The LogRhythm
case priority (1-5) is mapped to the OpenCTI incident severity.

## Requirements

- OpenCTI Platform >= 7.260609.0
- A reachable LogRhythm API gateway (Case API enabled)
- A LogRhythm API token (Bearer)

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

| Parameter       | config.yml        | Docker environment variable  | Default               | Mandatory | Description                                          |
| --------------- | ----------------- | ---------------------------- | --------------------- | --------- | --------------------------------------------------- |
| Connector ID    | `id`              | `CONNECTOR_ID`               | /                     | Yes       | A unique `UUIDv4` identifier for this connector.     |
| Connector Name  | `name`            | `CONNECTOR_NAME`             | `LogRhythm Incidents` | No        | Name of the connector.                              |
| Connector Scope | `scope`           | `CONNECTOR_SCOPE`            | `logrhythm`           | No        | The scope of the connector.                         |
| Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`        | `error`               | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).  |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD`  | `PT15M`               | No        | ISO-8601 period between two runs.                   |

### Connector extra parameters environment variables

| Parameter    | config.yml     | Docker environment variable          | Default | Mandatory | Description                                       |
| ------------ | -------------- | ------------------------------------ | ------- | --------- | ------------------------------------------------- |
| API base URL | `api_base_url` | `LOGRHYTHM_INCIDENTS_API_BASE_URL`   | /       | Yes       | Base URL of the LogRhythm API gateway.           |
| API token    | `api_token`    | `LOGRHYTHM_INCIDENTS_API_TOKEN`      | /       | Yes       | LogRhythm API token (Bearer).                    |
| Max cases    | `max_cases`    | `LOGRHYTHM_INCIDENTS_MAX_CASES`      | `200`   | No        | Maximum number of cases to fetch per run.        |
| TLP level    | `tlp_level`    | `LOGRHYTHM_INCIDENTS_TLP_LEVEL`      | `amber` | No        | TLP marking applied to imported incidents.       |
| SSL verify   | `ssl_verify`   | `LOGRHYTHM_INCIDENTS_SSL_VERIFY`     | `true`  | No        | Whether to verify the SSL certificate.           |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-logrhythm-incidents:rolling
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file from `config.yml.sample` and fill in the values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

On each run the connector fetches cases from the LogRhythm Case API (capped at
`max_cases`), converts each case to a STIX Case-Incident and sends the bundle to
OpenCTI. OpenCTI deduplicates case-incidents by their deterministic id across runs.
