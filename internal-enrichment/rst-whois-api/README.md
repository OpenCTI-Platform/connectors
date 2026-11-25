# OpenCTI RST WHOIS API Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Output Options](#output-options)
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

The [RST WHOIS API](https://www.rstcloud.com/rst-whois-api/) connector enriches domain and URL observables and indicators with domain registration data. It automatically retrieves WHOIS or RDAP data depending on which protocol is applicable for the domain.

Key features:
- Automatic WHOIS/RDAP protocol selection
- Effective TLD discovery for subdomains
- Real-time data retrieval
- No ban risk from WHOIS servers
- Raw response option
- Pay-as-you-go pricing model

---

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0
- RST Cloud API key ([Get one here](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22) or contact trial@rstcloud.net)
- Network access to RST Cloud API

---

## Configuration

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

In `config.yml`, these settings go in the `rst_whois_api` section (the legacy `rst-whois-api` section name is still accepted).

---

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-rst-whois-api:
    image: opencti/connector-rst-whois-api:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      # - CONNECTOR_NAME=RST WHOIS API
      # - CONNECTOR_SCOPE=Domain-Name,Url,indicator
      # - CONNECTOR_AUTO=false
      # - CONNECTOR_LOG_LEVEL=error
      # - CONNECTOR_MAX_TLP=TLP:AMBER+STRICT
      - RST_WHOIS_API_API_KEY=ChangeMe
      # - RST_WHOIS_API_BASE_URL=https://api.rstcloud.net/v1
      # - RST_WHOIS_API_TIMEOUT=10
      # - RST_WHOIS_API_WHOIS_OUTPUT_OBJECT=note
      # - RST_WHOIS_API_UPDATE_OUTPUT_ACTION=overwrite
      # - RST_WHOIS_API_OUTPUT_FORMAT=standard
      # - RST_WHOIS_API_OUTPUT_INCLUDE_RAW=false
    restart: always
```

### Manual Deployment

1. Clone the repository
2. Copy `src/config.yml.sample` to `src/config.yml` and configure
3. Install dependencies: `pip install -r requirements.txt`
4. Run the connector

---

## Usage

The connector enriches domains and URLs by:
1. Extracting domain from URLs if necessary
2. Querying RST WHOIS API for registration data
3. Adding WHOIS information to observable

Trigger enrichment:
- Manually via the OpenCTI UI
- Automatically if `CONNECTOR_AUTO=true`
- Via playbooks

---

## Behavior

### Data Flow

```mermaid
flowchart LR
    A[Domain/URL Observable] --> B[RST WHOIS API Connector]
    B --> C{Extract Domain}
    C --> D[RST Cloud API]
    D --> E[WHOIS/RDAP Data]
    E --> F{Output Target}
    F -->|Note| G[Create Note]
    F -->|Description| H[Update Description]
    G --> I[OpenCTI]
    H --> I
```

### Output Options

| Option | Description |
|--------|-------------|
| `note` | Create a Note object with WHOIS data |
| `description` | Update the observable description |

### Output Formats

| Format | Description |
|--------|-------------|
| `standard` | Basic WHOIS fields |
| `extended` | Additional WHOIS fields |

### Processing Details

1. **Subdomain Handling**: If the requested domain is a subdomain without registration data, the effective TLD is extracted and registration data is returned for that TLD
2. **Protocol Selection**: Automatically determines whether to use WHOIS or RDAP
3. **Real-time Data**: Domain registration data is fetched from live servers with short-lived caching

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug` to see:
- API request/response details
- Domain extraction logic
- WHOIS data processing

---

## Additional Information

- [RST Cloud](https://www.rstcloud.com/)
- [RST WHOIS API](https://www.rstcloud.com/rst-whois-api/)
- [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22)
- Contact: trial@rstcloud.net

### Key Benefits

- **No WHOIS Protocol Knowledge Required**: Automatically selects WHOIS or RDAP
- **No Bans**: Avoid being blocked by WHOIS servers during bulk enrichment
- **Consistent Output**: Always receive the same JSON format regardless of protocol
