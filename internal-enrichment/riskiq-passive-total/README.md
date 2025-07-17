# Depreciation of RiskIQ connector

> [!WARNING]  
> **This connector is now obsolete.**  
> Microsoft who acquired RiskIQ has decommissioned all RiskIQ's APIs and integrated RiskIQ data directly into their product. 
> The Community version is no longer functional.
> This connector will no longer be maintained. Please do not use it again.

# OpenCTI RISKIQ Passive Total enrichment connector

Table of Contents
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

The RiskIQ PassiveTotal enrichment connector can be used to enrich `IPv4-Addr` and `Domain-Name` observables with passive DNS data by creating STIX relationships based on different DNS record types.
[See RiskIQ PassiveTotal](https://community.riskiq.com).

## Installation

### Requirements

- OpenCTI Platform >= 6.3.5

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter           | config.yml | Docker environment variable | Default                 | Mandatory | Description                                                                              |
|---------------------|------------|-----------------------------|-------------------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID        | id         | `CONNECTOR_ID`              | /                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type      | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT         | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name      | name       | `CONNECTOR_NAME`            | /                       | Yes       | Name of the connector.                                                                   |
| Connector Scope     | scope      | `CONNECTOR_SCOPE`           | `IPv4-Addr,Domain-Name` | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Connector Log Level | log_level  | `CONNECTOR_LOG_LEVEL`       | info                    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto      | auto 	     | `CONNECTOR_AUTO`            | False                   | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |
 
### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                    | config.yml                    | Docker environment variable          | Default | Mandatory | Description                                                                                                           |
|------------------------------|-------------------------------|--------------------------------------|---------|-----------|-----------------------------------------------------------------------------------------------------------------------|
| RiskIQ username              | username                      | RISKIQ_USERNAME                      | /       | Yes       | The username for authenticating RiskIQ API requests.                                                                  |
| RiskIQ API Key               | api_key                       | RISKIQ_API_KEY                       | /       | Yes       | The API key for RiskIQ account access.                                                                                |
| Max TLP                      | max_tlp                       | RISKIQ_MAX_TLP                       | /       | No        | The maximal TLP of the observable being enriched.                                                                     |
| Import last seen time window | import_last_seen_time_window  | RISKIQ_IMPORT_LAST_SEEN_TIME_WINDOW  | `P30D`  | No        | Time window for importing data based on last-seen observations, using ISO duration format (e.g., 'P30D' for 30 days). |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from riskiq-passive-total/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

### Here's how each record type is handled:

`A Record`: `Resolves to an IPv4 address` and generates an IPv4-Addr observable with the STIX relationship `resolves-to` (Entity -> resolves-to -> IPv4).

`AAAA Record`: `Resolves to an IPv6 address` and generates an IPv6-Addr observable with the STIX relationship `resolves-to` (Entity -> resolves-to -> IPv6).

`SOA Record`: Resolves to an email address, generating an Email-Addr observable with the STIX relationship `related-to` (Entity -> related-to -> Email).

`SOA, MX, CNAME, NS Records`: `Resolve to domain names`, generating a Domain-Name observable with the STIX relationship `resolves-to` (Entity -> resolves-to -> Domain-Name).

`A Record (for domains)`: In specific cases as defined by RiskIQ, this `resolves to a domain`, creating a Domain-Name observable with a reversed STIX relationship `resolves-to` (Domain-Name -> resolves-to -> Entity).

### RiskIQ PassiveTotal API Endpoints used:

`/v2/account/quota`: This endpoint provides information about the user's current quota for the searchApi resource. It includes details about the user's current usage and the quota limits. This helps monitor whether the API usage is approaching or exceeding the allowed limits and includes information about the next reset time.

`/v2/dns/passive`: This endpoint allows querying the Passive DNS data for a specific entity, such as an IPv4 address or domain name. The response includes DNS records (such as A, AAAA, MX, SOA, etc.) associated with the provided entity, which can be used for enrichment in security and threat intelligence operations.


## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

## Additional information

The `RISKIQ_IMPORT_LAST_SEEN_TIME_WINDOW` environment variable specifies the time range used to filter imported data based on when it was last observed. This variable typically uses an ISO 8601 duration format (e.g., "P30D" for a 30-day window), allowing the connector to retrieve only records that have been observed within the specified period. This helps limit data to recent observations, optimizing performance and focusing on relevant, current information.