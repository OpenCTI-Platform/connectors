# OpenCTI Maltiverse Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Maltiverse connector imports threat intelligence data from the Maltiverse platform via TAXII 2.1 into OpenCTI.

## Table of Contents

- [OpenCTI Maltiverse Connector](#opencti-maltiverse-connector)
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

[Maltiverse](https://maltiverse.com) is a threat intelligence platform that aggregates and analyzes indicators of compromise from multiple sources. The platform provides access to curated threat feeds via a TAXII 2.1 server, making it compatible with STIX-based threat intelligence sharing.

This connector fetches STIX bundles from Maltiverse TAXII 2.1 collections and imports them directly into OpenCTI.

## Installation

### Requirements

- OpenCTI Platform >= 7.260722.0
- Maltiverse account with feed access
- TAXII 2.1 client library (`taxii2client`)

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-maltiverse:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-maltiverse:
    image: opencti/connector-maltiverse:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=MALTIVERSE
      - CONNECTOR_SCOPE=ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1
      - CONNECTOR_LOG_LEVEL=info
      - MALTIVERSE_USER=your@email.com
      - MALTIVERSE_PASSWD=ChangeMe
      - MALTIVERSE_FEEDS=VdhZV34B4jHUXfKt_gDi,another_feed_id
      - CONNECTOR_DURATION_PERIOD=PT4H
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

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

The connector runs automatically at the interval defined by `CONNECTOR_DURATION_PERIOD`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new data fetch.

## Behavior

The connector fetches STIX bundles from Maltiverse TAXII 2.1 collections and imports them into OpenCTI.

### Data Flow

```mermaid
graph LR
    subgraph Maltiverse
        direction TB
        TAXII[TAXII 2.1 Server]
        Collections[STIX Collections]
    end

    subgraph OpenCTI
        direction LR
        STIXObjects[STIX Objects]
    end

    TAXII --> Collections
    Collections --> STIXObjects
```

### Entity Mapping

The connector imports native STIX objects from Maltiverse. Common entity types include:

| Maltiverse Data  | OpenCTI Entity      | Description                                      |
|------------------|---------------------|--------------------------------------------------|
| IPv4/IPv6        | IPv4-Addr/IPv6-Addr | IP address observables                           |
| Domain           | Domain-Name         | Domain name observables                          |
| URL              | URL                 | URL observables                                  |
| File Hashes      | File                | File observables with MD5, SHA-1, SHA-256        |
| Vulnerability    | Vulnerability       | CVE and vulnerability data                       |
| Indicators       | Indicator           | STIX pattern indicators                          |

### Processing Details

1. **TAXII 2.1 Connection**: Authenticates with Maltiverse TAXII server using username/password
2. **Collection Filtering**: Only fetches collections matching the configured feed IDs
3. **Native STIX Import**: STIX bundles are sent directly to OpenCTI without transformation
4. **State Management**: Tracks last run timestamp to avoid redundant polling

### TAXII Endpoint

The connector uses the Maltiverse TAXII 2.1 server:
- **Server URL**: `https://api.maltiverse.com/taxii2/`
- **Authentication**: Basic authentication (username/password)

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- Last run timestamp
- Collection processing status
- Error messages for failed collection imports
- Next run timing information

## Additional information

- **Feed IDs**: Obtain feed/collection IDs from your Maltiverse account dashboard
- **Multiple Feeds**: Separate multiple feed IDs with commas (no spaces)
- **TAXII 2.1**: Uses the `taxii2client` library for TAXII 2.1 protocol
- **Native STIX**: Data is provided in STIX format and imported directly
- **Reference**: [Maltiverse Platform](https://maltiverse.com) | [Maltiverse Documentation](https://maltiverse.com/docs)
