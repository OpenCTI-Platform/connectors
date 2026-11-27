# OpenCTI RST IoC Lookup Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

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
  - [Enrichment Mapping](#enrichment-mapping)
  - [Generated STIX Objects](#generated-stix-objects)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

The [RST IoC Lookup](https://www.rstcloud.com/rst-ioc-lookup/) connector determines whether observables and indicators are malicious and worth detecting. It performs checks on IP addresses, domains, URLs, and hash values via the RST Cloud API.

Key features:
- Malware, threat actor, tool, CVE, and TTP enrichment
- Score and confidence adjustments
- External reference population
- ASN, geolocation, and WHOIS data enrichment
- Customizable detection flag threshold
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

In `config.yml`, the connector parameters go in the `rst_ioc_lookup` section (the legacy `rst-ioc-lookup` section name is still accepted).

---

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-rst-ioc-lookup:
    image: opencti/connector-rst-ioc-lookup:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=RST IoC Lookup
      - CONNECTOR_SCOPE=IPv4-Addr,Domain-Name,Url,StixFile,indicator
      - CONNECTOR_AUTO=false
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_MAX_TLP=TLP:AMBER+STRICT
      - RST_IOC_LOOKUP_BASE_URL=https://api.rstcloud.net/v1
      - RST_IOC_LOOKUP_API_KEY=ChangeMe
      - RST_IOC_LOOKUP_UPDATE_CONFIDENCE=true
      - RST_IOC_LOOKUP_UPDATE_SCORE=true
      - RST_IOC_LOOKUP_UPDATE_VALID_FROM=true
      - RST_IOC_LOOKUP_LABEL_FORMAT=short
      - RST_IOC_LOOKUP_SCORE_TYPE=last
      - RST_IOC_LOOKUP_UPDATE_DESCRIPTION_ACTION=overwrite
      - RST_IOC_LOOKUP_DETECTION_FLAG_THRESHOLD=45
      - RST_IOC_LOOKUP_TIMEOUT=10
    restart: always
```

### Manual Deployment

1. Clone the repository
2. Copy `config.yml.sample` to `config.yml` and configure
3. Install dependencies: `pip install -r requirements.txt`
4. Run the connector

---

## Usage

The connector enriches observables and indicators by:
1. Checking maliciousness via RST Cloud API
2. Enriching with related threat intelligence
3. Adjusting scores and confidence
4. Setting detection flags based on threshold

Trigger enrichment:
- Manually via the OpenCTI UI
- Automatically if `CONNECTOR_AUTO=true`
- Via playbooks

---

## Behavior

### Data Flow

```mermaid
flowchart LR
    A[Observable/Indicator] --> B[RST IoC Lookup]
    B --> C{RST Cloud API}
    C --> D[Threat Data]
    D --> E[Malware/Actors]
    D --> F[TTPs/CVEs]
    D --> G[Score/Confidence]
    E --> H[OpenCTI]
    F --> H
    G --> H
```

### Enrichment Mapping

| Observable Type | Enrichment Data | Description |
|-----------------|-----------------|-------------|
| IPv4-Addr | ASN, GeoIP, Reputation | IP threat intelligence |
| Domain-Name | WHOIS, Reputation | Domain threat intelligence |
| URL | Analysis, Reputation | URL threat intelligence |
| StixFile | Hash Analysis | File hash reputation |
| Indicator | Full Context | Pattern-based enrichment |

### Score Types

| Type | Description |
|------|-------------|
| `last` | Score calculated at time of last_seen |
| `total` | Decayed score based on time since last_seen |

### Generated STIX Objects

| Object Type | Description |
|-------------|-------------|
| Malware | Related malware families |
| Threat-Actor | Associated threat actors |
| Tool | Related tools |
| Attack-Pattern | MITRE ATT&CK TTPs |
| Vulnerability | Related CVEs |
| Labels | Threat classification |
| External Reference | Source references |

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug` to see:
- API request/response details
- Score calculations
- Enrichment processing

---

## Additional Information

- [RST Cloud](https://www.rstcloud.com/)
- [RST IoC Lookup](https://www.rstcloud.com/rst-ioc-lookup/)
- [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22)
- Contact: trial@rstcloud.net
