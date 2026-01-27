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

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter         | config.yml      | Docker environment variable   | Default        | Mandatory | Description                                                                    |
|-------------------|-----------------|-------------------------------|----------------|-----------|--------------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`                |                | Yes       | A unique `UUIDv4` identifier for this connector instance.                      |
| Connector Name    | name            | `CONNECTOR_NAME`              | Google DTM     | No        | Name of the connector.                                                         |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`             | google-dtm     | Yes       | Comma-separated observable types to import.                                    |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`         | error          | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.     |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD`   | PT1H           | No        | Time interval between connector runs in ISO 8601 format. Each hour by default. |

### Connector extra parameters environment variables

| Parameter         | config.yml                   | Docker environment variable       | Default       | Mandatory | Description                                                                                                                                                                                                                                                           |
|-------------------|------------------------------|-----------------------------------|---------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| API Key           | google_dtm.api_key           | GOOGLE_DTM_API_KEY                | /             | Yes       | Google DTM API Key                                                                                                                                                                                                                                                    |
| TLP               | google_dtm.tlp               | GOOGLE_DTM_TLP                    | amber+strict  | No        | Default Traffic Light Protocol (TLP) marking for imported data. Available values are: clear, white, green, amber, amber+strict, red. Default: 'amber+strict'                                                                                                          |
| Import Start Date | google_dtm.import_start_date | GOOGLE_DTM_IMPORT_START_DATE      | P10D          | No        | ISO 8601 duration string specifying how far back to import reports (e.g., P1D for 1 day, P7D for 7 days). Default: 'P10D'                                                                                                                                             |
| Alert Type        | google_dtm.alert_type        | GOOGLE_DTM_ALERT_SEVERITY         |               | No        | Comma-separated list of alert types to ingest. Leave blank to retrieve alerts of all types. Available values are: "Compromised Credentials, Domain Discovery, Email, Forum Post, Message, Paste, Shop Listing, Tweet, Web Content". Default: empty (all alert types)  |
| Alert Severity    | google_dtm.alert_severity    | GOOGLE_DTM_ALERT_TYPE             |               | No        | Comma-separated list of alert severities to ingest. Leave blank to retrieve alerts of all severities. Available values are: "high, medium, low". Default: empty (all alert severities)                                                                                |

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
      - GOOGLE_DTM_IMPORT_START_DATE=PD10
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