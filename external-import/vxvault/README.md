# OpenCTI VX Vault Connector

The VX Vault connector imports URLs of potential malicious payloads from [VX Vault](http://vxvault.net) into OpenCTI as STIX 2.1 URL observables.

## Table of Contents

- [OpenCTI VX Vault Connector](#opencti-vx-vault-connector)
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

[VX Vault](http://vxvault.net) is a public repository that tracks URLs associated with potential malicious payloads. This connector periodically fetches the VX Vault URL list and imports the URLs as STIX 2.1 URL observables into OpenCTI, marked with TLP:WHITE.

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Python >= 3.11

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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
