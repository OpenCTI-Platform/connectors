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
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Mapping to OpenCTI entities](#mapping-to-opencti-entities)
  - [Debugging](#debugging)

## Introduction

This connector fetches SIEM rule alerts from the Google SecOps API and imports them into OpenCTI as STIX 2.1 objects. Each rule alert is mapped to an OpenCTI Incident, enriched with related observables (IP addresses, hostnames, user accounts, files) and linked via STIX relationships.

The connector uses backward-sliding pagination: within a run, when a window returns too many alerts it slides the window end backward to the earliest alert seen and re-queries; on first run it fetches alerts back to a configurable lookback window; on subsequent runs it resumes from the last processed alert timestamp.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- Google SecOps access with a GCP service account authorized for the `https://www.googleapis.com/auth/cloud-platform` scope
- Google SecOps project ID, region, instance UUID, and service account credentials

## Configuration variables

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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
| Rule alert                   | Incident                      |
| `principal_ip` outcome       | IPv4 / IPv6 Address           |
| `principal_hostname`         | Hostname                      |
| `principal_user` outcome     | User Account                  |
| File outcome                 | File (with SHA-256 hash)      |
| Alert → Observable links     | `related-to` Relationships    |
| `target_url` outcome  | URL |
| `principal_user_email_addresses` + `target_user_email_addresses` outcome  | EmailAddress |
| `mitre_attack_technique_id` outcome  | AttackPattern |

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
