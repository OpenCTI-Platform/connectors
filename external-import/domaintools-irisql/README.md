# OpenCTI DomainTools IrisQL Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | -          | -       |

## Table of Contents

- [OpenCTI DomainTools IrisQL Connector](#opencti-domaintools-irisql-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector uses IrisQL to fetch data from DomainTools Iris Investigate and import it into OpenCTI. It maps each query result to a STIX 2.1 Observable, enriching it with context like IP addresses, name servers, mail servers, email addresses, etc. To ensure secure data handling, all created objects are assigned a Traffic Light Protocol (TLP) marking for downstream sharing.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- DomainTools API credential

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==6.5.1`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

Register connector in the **main** OpenCTI `docker-compose.yml`:

```yaml
  connector-domaintools:
    image: opencti/connector-domaintools-irisql:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=changeme
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=DomainTools IrisQL
      - CONNECTOR_SCOPE=stix2
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT5M
      - DOMAINTOOLS_API_BASE_URL=https://api.domaintools.com/v1/iris-investigate/
      - DOMAINTOOLS_API_KEY=changeme
      - |-
        DOMAINTOOLS_IRIS_QL=# IrisQL-1.0
        domain contains "sso"
        AND
        first_seen within "the last 3 hour"
        AND
        risk_score greater_than_or_equal "90"
      - DOMAINTOOLS_STORE_IRIS_DATA=true
      - DOMAINTOOLS_TLP_LEVEL=clear
    restart: always
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`.

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for your environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

After installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of data, navigate to:

**Data management → Ingestion → Connectors** in the OpenCTI platform.

Find the "DomainTools IrisQL" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

- Converts each query result into a STIX 2.1 Observable object
- Bundles and sends the STIX objects to OpenCTI

## Debugging

The connector can be debugged by setting the appropriate log level. Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, for example, `self.helper.connector_logger.error("An error message")`.

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. Log output includes:

- API call details and retry behavior
- Data count fetched per run
- Page-by-page fetch progress
- STIX conversion trace per entry
- Bundle send status

## Additional information

- Each Iris Investigate result becomes a STIX 2.1 Domain-Name observable, carrying the DomainTools risk score and per-component risk labels (proximity, malware, phishing, spam).
- Related infrastructure is expanded into its own observables and linked with STIX relationships: resolving IP addresses (`resolves-to`), mail and name servers (`resolves-to`, with their IPs `related-to`), and registrant, SOA, SSL, and additional WHOIS email addresses (`related-to`).
- When `DOMAINTOOLS_STORE_IRIS_DATA` is enabled, the raw Iris record for each domain is attached as a STIX Note.
- Every object is attributed to a DomainTools author identity and tagged with the configured TLP marking.
