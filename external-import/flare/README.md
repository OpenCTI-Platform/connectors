# OpenCTI Flare Connector
The Flare connector integrates OpenCTI with the Flare platform by ingesting events from a tenant feed as STIX 2.1 Incidents.
## Table of Contents
- [OpenCTI Flare Connector](#opencti-flare-connector)
    - [Table of Contents](#table-of-contents)
    - [Introduction](#introduction)
    - [Installation](#installation)
        - [Requirements](#requirements)
    - [Configuration variables](#configuration-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Usage](#usage)

## Introduction
This connector fetches events from the Flare API and imports them into OpenCTI as Incidents with related observables and metadata such as severity, incident type and relevant dates.

## Installation
### Requirements
- Flare API Key

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment
### Docker Deployment
1. Ensure `pycti` version in `requirements.txt` matches your OpenCTI version (e.g., `pycti==6.8.10`).
2. Build Docker image:
```bash
docker build -t opencti/connector-flare:rolling .
```
3. Register connector in the **main** OpenCTI `docker-compose.yml`:
```yaml
  connector-flare:
  image: opencti/connector-flare:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=Flare
      - CONNECTOR_SCOPE=Incident,Observable,Indicator
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - FLARE_API_BASE_URL=api.flare.io
      - FLARE_API_KEY=fw_xxxxxx
      - FLARE_TENANT_ID=changeme
      - FLARE_EVENT_TYPES=changeme
      - FLARE_EVENT_ACTIONS=changeme
      - FLARE_LOOKBACK_DAYS=30
      - FLARE_TLP_LEVEL=white
    restart: always
```
4. Start the connector:
```bash
docker compose up -d
```
> 🔁 Do not use the local `docker-compose.yml`. Always integrate the connector in OpenCTI’s main `docker-compose.yml`.

### Manual Deployment
1. Copy and configure `config.yml` from the provided `config.yml.sample`
2. Install dependencies:
```bash
pip3 install -r src/requirements.txt
```
3. Start the connector:
```bash
python3 src/connector.py
```

## Usage
The connector runs automatically at the interval set by `duration_period`. You can also manually trigger it from:

**OpenCTI → Data Management → Ingestion → Connectors**

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.
