# OpenCTI Google SecOps SIEM Incidents Connector

| Status | Date | Comment |
|--------|------|---------|
| Verified | - | - |

## Table of Contents

- [OpenCTI Google SecOps SIEM Incidents Connector](#opencti-google-secops-siem-incidents-connector)
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
    - [Mapping to OpenCTI entities](#mapping-to-opencti-entities)
  - [Debugging](#debugging)

## Introduction

This connector fetches SIEM rule alerts from the Google SecOps API and imports them into OpenCTI as STIX 2.1 objects. Each rule alert is mapped to an OpenCTI Incident, enriched with related observables (IP addresses, hostnames, user accounts, files) and linked via STIX relationships.

The connector uses forward-sliding pagination: on first run it fetches alerts back to a configurable lookback window; on subsequent runs it resumes from the last processed alert timestamp.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- Google SecOps access with a GCP service account authorized for the `https://www.googleapis.com/auth/cloud-platform` scope
- Google SecOps project ID, region, instance UUID, and service account credentials

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml `opencti` | Docker environment variable | Default | Mandatory | Description                                          |
|---------------|----------------------|-----------------------------|---------|-----------|------------------------------------------------------|
| OpenCTI URL   | `url`                | `OPENCTI_URL`               | /       | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`              | `OPENCTI_TOKEN`             | /       | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml `connector` | Docker environment variable | Default                       | Mandatory | Description                                                                            |
|-----------------|------------------------|-----------------------------|-------------------------------|-----------|----------------------------------------------------------------------------------------|
| Connector ID    | `id`                   | `CONNECTOR_ID`              | /                             | Yes       | A unique `UUIDv4` identifier for this connector instance.                              |
| Connector Name  | `name`                 | `CONNECTOR_NAME`            | `Google SecOps`               | No        | Display name of the connector.                                                         |
| Connector Scope | `scope`                | `CONNECTOR_SCOPE`           | `google-secops-siem-incidents`| No        | Scope token used to route messages to this connector.                                  |
| Log Level       | `log_level`            | `CONNECTOR_LOG_LEVEL`       | `error`                       | No        | Verbosity of logs. Options: `debug`, `info`, `warn`, `error`.                          |
| Duration Period | `duration_period`      | `CONNECTOR_DURATION_PERIOD` | `PT1H`                        | No        | Interval between two connector runs (ISO 8601 duration format).                        |

### Connector extra parameters environment variables

| Parameter               | Docker environment variable                                    | Default                                  | Mandatory | Description                                                                                      |
|-------------------------|----------------------------------------------------------------|------------------------------------------|-----------|--------------------------------------------------------------------------------------------------|
| Base URL                | `GOOGLE_SECOPS_SIEM_INCIDENTS_BASE_URL`              | `https://chronicle.googleapis.com`       | No        | Google SecOps API base URL. A region prefix is prepended at runtime.                             |
| GCP project ID          | `GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_ID`            | /                                        | Yes       | Google Cloud project ID associated with the Google SecOps instance.                              |
| Region                  | `GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_REGION`        | /                                        | Yes       | Google SecOps region prefix (e.g. `us`, `eu`, `asia`).                                           |
| Instance                | `GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_INSTANCE`      | /                                        | Yes       | Google SecOps instance UUID.                                                                     |
| Private key (PEM)       | `GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY`           | /                                        | Yes       | Service account private key in PEM format.                                                       |
| Private key ID          | `GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY_ID`        | /                                        | Yes       | Service account private key ID.                                                                  |
| Client email            | `GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_EMAIL`          | /                                        | Yes       | Service account client email (`*@*.iam.gserviceaccount.com`).                                    |
| Client ID               | `GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_ID`             | /                                        | Yes       | Service account client ID (numeric).                                                             |
| Client cert URL         | `GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_CERT_URL`       | /                                        | Yes       | Service account client certificate URL.                                                          |
| TLP level               | `GOOGLE_SECOPS_SIEM_INCIDENTS_TLP_LEVEL`                       | `amber`                                  | No        | TLP marking applied to all imported entities. Values: `clear`, `white`, `green`, `amber`, `amber+strict`, `red`. |
| First start time        | `GOOGLE_SECOPS_SIEM_INCIDENTS_FIRST_START_TIME`                | `P1D`                                    | No        | How far back to fetch alerts on the very first run (ISO 8601 duration). Only used when no prior state exists. |

> **Tip — service account JSON:** All credential fields map directly to the fields inside a GCP service account JSON key file. You can source them from there directly.

## Deployment

### Docker Deployment

Before building the Docker image, set the version of `pycti` in `requirements.txt` to match your OpenCTI platform version (e.g. `pycti==6.5.1`).

Register the connector in your main OpenCTI `docker-compose.yml`:

```yaml
  connector-google-secops-siem-incidents:
    image: opencti/connector-google-secops-siem-incidents:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=Google SecOps
      - GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_ID=my-gcp-project
      - GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_REGION=us
      - GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_INSTANCE=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----
      - GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY_ID=ChangeMe
      - GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_EMAIL=my-sa@my-project.iam.gserviceaccount.com
      - GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_ID=123456789
      - GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_CERT_URL=https://www.googleapis.com/robot/v1/metadata/x509/...
    restart: always
```

Then start the stack:

```shell
docker compose up -d
```

### Manual Deployment

Install dependencies (preferably in a virtual environment):

```shell
pip install -r requirements.txt
```

Start the connector from the `src` directory:

```shell
python main.py
```

## Usage

After installation the connector runs automatically at the interval defined by `CONNECTOR_DURATION_PERIOD`.

To force an immediate run, navigate to **Data management → Ingestion → Connectors** in OpenCTI, find the **Google SecOps** connector, and click the refresh button to reset its state.

## Behavior

- On **first run**, fetches alerts from `now - FIRST_START_TIME` to `now`.
- On **subsequent runs**, resumes from the last processed alert `detection_timestamp + 1s` (persisted in connector state as `last_alert_timestamp`); the +1s offset ensures the boundary alert is not re-fetched on the next run.
- If the API returns `tooManyAlerts=true`, the query window slides **backward**: the `endTime` is replaced by the oldest `detection_timestamp` in the current batch, and fetching continues until all pages are consumed.
- Each alert batch is converted to STIX objects and sent as a bundle before advancing state — ensuring no data loss on partial runs.
- If a paginated run is **interrupted** (crash, restart), the connector persists a `pagination_checkpoint` after each truncated batch. On the next run it detects the checkpoint and resumes the backward-pagination window from where it left off, then clears the checkpoint on clean completion.

### Mapping to OpenCTI entities

| Google SecOps source         | OpenCTI / STIX 2.1 entity      |
|------------------------------|-------------------------------|
| Rule alert                 | Incident                      |
| `principal_ip` outcome     | IPv4 / IPv6 Address           |
| `principal_hostname`       | Hostname                      |
| `principal_user` outcome   | User Account                  |
| File outcome               | File (with SHA-256 hash)      |
| Alert → Observable links   | `related-to` Relationships    |

All entities are tagged with the configured TLP marking and attributed to a **Google SecOps** organization identity.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose output. With debug enabled, logs include:

- Connector state (last processed timestamp)
- Per-batch alert counts and pagination decisions
- STIX bundle size before send
- Session open / close lifecycle
- Authentication refresh events

Common errors and their causes:

| Error message | Likely cause |
|---|---|
| `Google authentication failed` | Invalid or expired service account key — check `client_email` and `private_key` in your credentials. |
| `invalid_grant: account not found` | The service account does not exist or has been deleted in GCP. |
| `Invalid IP V4 address` | Google SecOps returned an empty IP string in an alert outcome — safe to ignore, patched from version X. |
