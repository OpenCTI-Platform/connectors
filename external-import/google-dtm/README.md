# OpenCTI Google Digital Threat Monitoring Connector

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

The Google Digital Threat Monitoring (DTM) connector retrieves threat alerts and contextual information from the Google Digital Threat Monitoring API and ingests them into OpenCTI in the form of STIX 2.1 incidents and associated observables (domains, URLs, IP addresses, and email addresses).

## Table of Contents

- [OpenCTI Google Digital Threat Monitoring Connector](#opencti-google-digital-threat-monitoring-connector)
    - [Table of Contents](#table-of-contents)
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
    - [Debugging](#debugging)
    - [Additional information](#additional-information)

## Introduction

Google Digital Threat Monitoring (DTM) is an external threat intelligence service that continuously monitors the open web, dark web, and other online sources to identify threats targeting your brand, domains, executives, and assets. By providing contextualized alerts and curated intelligence, DTM helps organizations detect and respond quickly to phishing, impersonation, data leakage, and other digital risks. 
This connector integrates Google Digital Threat Monitoring (DTM) service with OpenCTI to bring external digital risk insights directly into your threat intelligence platform. 
The connector periodically pulls alerts from the DTM API and ingests each alert into OpenCTI as an Incident. 
For every Incident, it stores the available context from DTM (threat category, severity, timestamps, sources, and descriptive details) and links all related technical artifacts—indicators and observables like domains, URLs, IP addresses, accounts, and file hashes.

By integrating DTM alerts as Incidents in OpenCTI and attaching their associated observables, the connector provides a structured, centralized view of external digital threats and makes it easier to correlate them with other intelligence feeds and internal security data.

## Installation

### Requirements

- OpenCTI Platform >= 6.9.x
- Google DTM API key

## Configuration

Configuration parameters can be provided in either **`config.yml`** file, **`.env`** file or directly as **environment variables** (e.g. from **`docker-compose.yml`** for Docker deployments).

Priority: **YAML > .env > environment > defaults**.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-google-dtm:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-google-dtm:
    image: opencti/connector-google-dtm:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - "CONNECTOR_NAME=Google DTM"
      - CONNECTOR_SCOPE=google-dtm
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT1H
      - GOOGLE_DTM_API_KEY=ChangeMe
      - GOOGLE_DTM_TLP=red
      - GOOGLE_DTM_IMPORT_START_DATE=P10D
      - GOOGLE_DTM_ALERT_SEVERITY=
      - GOOGLE_DTM_ALERT_TYPE=
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector:

```bash
python3 -m src 
```

## Usage

The connector runs automatically at the interval defined by `CONNECTOR_DURATION_PERIOD`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new sync.

## Behavior

The connector imports Google DTM alerts as Incidents and Observables (Domain, URL, IP, Email).

## Debugging

```env
CONNECTOR_LOG_LEVEL=debug
```

## Additional information

- **TLP Levels**: Supports `white`, `green`, `amber`, `amber+strict`, `red`
- **Reference**: [Google DTM API Documentation](https://gtidocs.virustotal.com/reference/get-alerts)