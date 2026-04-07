# OpenCTI VX Vault Connector

The VX Vault connector imports URLs of potential malicious payloads from [VX Vault](http://vxvault.net) into OpenCTI as STIX 2.1 URL observables.

## Table of Contents

- [OpenCTI VX Vault Connector](#opencti-vx-vault-connector)
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

[VX Vault](http://vxvault.net) is a public repository that tracks URLs associated with potential malicious payloads. This connector periodically fetches the VX Vault URL list and imports the URLs as STIX 2.1 URL observables into OpenCTI, marked with TLP:WHITE.

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Python >= 3.11

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter         | config.yml      | Docker environment variable  | Default            | Mandatory | Description                                                                            |
| ----------------- | --------------- | ---------------------------- | ------------------ | --------- | -------------------------------------------------------------------------------------- |
| Connector ID      | id              | `CONNECTOR_ID`               | /                  | Yes       | A unique `UUIDv4` identifier for this connector instance.                              |
| Connector Type    | type            | `CONNECTOR_TYPE`             | EXTERNAL_IMPORT    | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                          |
| Connector Name    | name            | `CONNECTOR_NAME`             | VX Vault URL list  | Yes       | Name of the connector.                                                                 |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`            | vxvault            | Yes       | The scope or type of data the connector is importing.                                  |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`        | info               | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD`  | P3D                | Yes       | ISO 8601 duration between connector runs (e.g., `P3D` for 3 days, `PT12H` for 12h).   |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter         | config.yml        | Docker environment variable  | Default                             | Mandatory | Description                                                    |
| ----------------- | ----------------- | ---------------------------- | ----------------------------------- | --------- | -------------------------------------------------------------- |
| VXVault URL       | url               | `VXVAULT_URL`                | https://vxvault.net/URL_List.php    | No        | The URL of the VX Vault dataset to fetch.                      |
| Create Indicators | create_indicators | `VXVAULT_CREATE_INDICATORS`  | true                                | No        | If true, create indicators from the imported URLs.             |
| SSL Verify        | ssl_verify        | `VXVAULT_SSL_VERIFY`         | false                               | No        | Whether to verify SSL certificates when fetching the dataset.  |

> **Deprecated:** `VXVAULT_INTERVAL` (polling interval in days) is deprecated. Use `CONNECTOR_DURATION_PERIOD` instead. The old variable is still accepted for backward compatibility.

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-vxvault:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
connector-vxvault:
  image: opencti/connector-vxvault:latest
  environment:
    - OPENCTI_URL=http://localhost
    - OPENCTI_TOKEN=ChangeMe
    - CONNECTOR_ID=ChangeMe
    - CONNECTOR_NAME=VX Vault URL list
    - CONNECTOR_SCOPE=vxvault
    - CONNECTOR_LOG_LEVEL=info
    - CONNECTOR_DURATION_PERIOD=P3D
    - VXVAULT_URL=https://vxvault.net/URL_List.php
    - VXVAULT_CREATE_INDICATORS=true
    - VXVAULT_SSL_VERIFY=false
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
cd src
python3 main.py
```

## Usage

The connector runs automatically at the interval defined by `CONNECTOR_DURATION_PERIOD`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new import.

## Behavior

On each run, the connector:

1. Fetches the VX Vault URL list from the configured endpoint
2. Parses the response, skipping header lines and HTML tags
3. Creates a STIX 2.1 URL observable for each valid URL, marked with TLP:WHITE and a score of 80
4. Sends the resulting STIX bundle to OpenCTI

All imported URLs are attributed to the "VX Vault" organization identity.

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

## Additional information

- **Data Source**: [VX Vault](http://vxvault.net)
- **Source Code**: [GitHub](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/vxvault)
