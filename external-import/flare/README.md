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

By default events come from the tenant feed. Set `FLARE_IDENTIFIER_GROUP_ID` to fetch only the events matching the identifiers of a single identifier group instead.

## Installation
### Requirements
- Flare API Key

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment
### Docker Deployment
1. Build Docker image:
```bash
docker build -t opencti/connector-flare:rolling .
```
2. Register connector in the **main** OpenCTI `docker-compose.yml`:
```yaml
  connector-flare:
    image: opencti/connector-flare:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=Flare
      - CONNECTOR_SCOPE=Flare
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - FLARE_API_DOMAIN=api.flare.io
      - FLARE_API_KEY=fw_xxxxxx
      #- FLARE_TENANT_ID= # optional, Flare tenant ID
      #- FLARE_IDENTIFIER_GROUP_ID= # optional, fetch events from this identifier group's feed instead of the tenant feed
      #- FLARE_EVENT_TYPES=stealer_log,domain,ransomleak,leak # optional (default: 'stealer_log,domain,ransomleak,leak')
      #- FLARE_EVENT_ACTIONS= # optional, filter by event actions: 'ignored', 'remediated' (default: none)
      #- FLARE_SEVERITIES= # optional, filter by severities: 'info', 'low', 'medium', 'high', 'critical' (default: none, all severities)
      - FLARE_LOOKBACK_DAYS=30
      - FLARE_TLP_LEVEL=white
    restart: always
```
3. Start the connector:
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
python3 src/main.py
```

## Usage
The connector runs automatically at the interval set by `duration_period`. You can also manually trigger it from:

**OpenCTI → Data Management → Ingestion → Connectors**

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.
