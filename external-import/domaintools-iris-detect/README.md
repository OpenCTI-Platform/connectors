# OpenCTI DomainTools Iris Detect Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | -          | -       |

## Table of Contents

- [OpenCTI DomainTools Iris Detect Connector](#opencti-domaintools-iris-detect-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [DomainTools extra parameters environment variables](#domaintools-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)
  - [Related resources](#related-resources)

## Introduction

This connector fetches domain data from DomainTools Iris Detect, a DomainTools product for monitoring newly registered domains, and imports it into OpenCTI. It is intended for threat intelligence teams who want to track brand-proximity or malicious domains inside their OpenCTI instance. The connector maps each result to a Structured Threat Information Expression (STIX) 2.1 Observable, enriching it with context like IP addresses, name servers, and mail servers. The connector assigns a Traffic Light Protocol (TLP) marking to all created objects for downstream sharing.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- Python 3.x (for manual deployment)
- DomainTools API key (available from your DomainTools account)

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Before building the Docker container, set the version of `pycti` (the OpenCTI Python SDK) in `requirements.txt` to match your OpenCTI version — for example, `pycti==6.5.1`. If you omit the version, the latest `pycti` is installed, which can fail to initialize against older OpenCTI releases.

Build a Docker Image using the provided `Dockerfile`.

Example:

Register connector in the **main** OpenCTI `docker-compose.yml`:

```yaml
  connector-domaintools-iris-detect:
    image: opencti/connector-domaintools-iris-detect:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=changeme
      - CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - CONNECTOR_NAME=DomainTools Iris Detect
      - CONNECTOR_SCOPE=stix2
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT5M
      - DOMAINTOOLS_API_BASE_URL=https://api.domaintools.com/v1/iris-detect/
      - DOMAINTOOLS_API_KEY=changeme
      - DOMAINTOOLS_MONITOR_ID=changeme
      - DOMAINTOOLS_STORE_IRIS_DATA=true
      - DOMAINTOOLS_PREVIEW=false
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

Find the "DomainTools Iris Detect" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

- Fetches new domain results from the Iris Detect API on each run interval
- Converts each result into a STIX 2.1 Domain-Name observable, carrying the DomainTools risk score and per-component risk labels (proximity, malware, phishing, spam)
- Expands related infrastructure into its own observables and links them with STIX relationships: resolving IP addresses (`resolves-to`), mail and name servers (`resolves-to`, with their IPs `related-to`)
- Bundles and sends the STIX objects to OpenCTI

After the first successful run, Domain-Name observables appear under **Observations** in the OpenCTI platform, each linked to its infrastructure and tagged with the configured TLP marking.

## Debugging

The connector can be debugged by setting the appropriate log level. Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, for example, `self.helper.connector_logger.error("An error message")`.

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. Log output includes:

- API call details and retry behavior
- Data count fetched per run
- Page-by-page fetch progress
- STIX conversion trace per entry
- Bundle send status

## Additional information

- When `DOMAINTOOLS_STORE_IRIS_DATA` is `true`, the connector attaches the raw Iris Detect record for each domain as a STIX Note.
- The connector attributes every created object to a DomainTools author identity and tags it with the configured TLP marking.

## Related resources

- [DomainTools Iris Detect product page](https://www.domaintools.com/products/iris-detect/)
- [DomainTools API documentation](https://api.domaintools.com/)
- [DomainTools Feeds OpenCTI connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/domaintools-feeds)
- [DomainTools IrisQL OpenCTI connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/domaintools-irisql)
