# OpenCTI BitSight External Import Connector

This connector imports actionable alerts from the BitSight (Cybersixgill) API into OpenCTI.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)

## Introduction

The BitSight connector fetches actionable alerts from the Cybersixgill API and converts them to STIX 2.1 bundles for ingestion into OpenCTI. It supports both single-tenant and multi-tenant modes.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.13
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library

## Configuration variables

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml      | Docker environment variable  | Default         | Mandatory | Description                                                    |
| --------------- | --------------- | ---------------------------- | --------------- | --------- | -------------------------------------------------------------- |
| Connector ID    | id              | `CONNECTOR_ID`               | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.      |
| Connector Type  | type            | `CONNECTOR_TYPE`             | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.  |
| Connector Name  | name            | `CONNECTOR_NAME`             | BitSight        | No        | Name of the connector.                                         |
| Connector Scope | scope           | `CONNECTOR_SCOPE`            |                 | Yes       | The scope or type of data the connector is importing.          |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`        | error           | No        | Determines the verbosity of the logs.                          |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD`  | PT1H            | No        | Interval in ISO-8601 format between two runs.                  |

### Connector extra parameters environment variables

| Parameter     | config.yml    | Docker environment variable | Default | Mandatory | Description                                        |
| ------------- | ------------- | --------------------------- | ------- | --------- | -------------------------------------------------- |
| Client ID     | client_id     | `BITSIGHT_CLIENT_ID`        |         | Yes       | Client ID for Cybersixgill API authentication.     |
| Client Secret | client_secret | `BITSIGHT_CLIENT_SECRET`    |         | Yes       | Client secret for Cybersixgill API authentication. |
| TLP Level     | tlp_level     | `BITSIGHT_TLP_LEVEL`        | clear   | No        | Default TLP marking for imported entities.         |

## Deployment

### Docker Deployment

```shell
docker build . -t opencti/connector-bitsight:latest
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on `config.yml.sample`, then:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Usage

The connector runs automatically at the configured interval. To force a run, navigate to `Data management` -> `Ingestion` -> `Connectors` in OpenCTI and click the refresh button.

## Behavior

The connector follows this flow:

1. **Authenticate** — Obtains a bearer token (valid 30 min) via `/auth/token`
2. **List organisations** — Retrieves monitored organisations for multi-tenant mode via `/multi-tenant/organization`
3. **Fetch alerts** — Gets recent actionable alerts via `/alerts/actionable-alert`
4. **Get alert details** — Retrieves full details per alert via `/alerts/actionable_alert/{id}`
5. **Get alert content** — Fetches supplementary content via `/actionable_alert_content/{id}`
6. **Convert & send** — Converts alerts to STIX Incident objects and sends bundles to OpenCTI

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging.

