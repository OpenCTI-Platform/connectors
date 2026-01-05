# OpenCTI GreyNoise Feed Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The GreyNoise Feed connector imports internet scanner IP addresses from GreyNoise Intelligence into OpenCTI as indicators and observables.

## Table of Contents

- [OpenCTI GreyNoise Feed Connector](#opencti-greynoise-feed-connector)
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

GreyNoise provides intelligence on internet-wide scanners, botnets, and other sources of internet background noise. This connector uses the GreyNoise Feed API to import IP addresses observed scanning the internet, including contextual information about their behavior, associated vulnerabilities, and classifications.

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- GreyNoise subscription with Feed access
- GreyNoise API key

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter         | config.yml      | Docker environment variable   | Default        | Mandatory | Description                                                                 |
|-------------------|-----------------|-------------------------------|----------------|-----------|-----------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`                |                | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name    | name            | `CONNECTOR_NAME`              | GreyNoise Feed | No        | Name of the connector.                                                      |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`             | greynoise      | No        | The scope or type of data the connector is importing.                       |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`         | info           | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.  |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD`   | PT1H           | No        | Time interval between connector runs in ISO 8601 format.                    |

### Connector extra parameters environment variables

| Parameter      | config.yml            | Docker environment variable   | Default | Mandatory | Description                                      |
|----------------|----------------------|-------------------------------|---------|-----------|--------------------------------------------------|
| API Key        | greynoise.api_key    | `GREYNOISE_API_KEY`           |         | Yes       | GreyNoise API key.                               |
| Feed Type      | greynoise.feed_type  | `GREYNOISE_FEED_TYPE`         |         | No        | Type of GreyNoise feed to import.                |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-greynoise-feed:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-greynoise-feed:
    image: opencti/connector-greynoise-feed:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=GreyNoise Feed
      - CONNECTOR_SCOPE=greynoise
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - GREYNOISE_API_KEY=ChangeMe
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
python3 main.py
```

## Usage

The connector runs automatically at the interval defined by `CONNECTOR_DURATION_PERIOD`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new sync.

## Behavior

The connector fetches IP addresses from the GreyNoise Feed API and imports them as indicators and observables.

### Data Flow

```mermaid
graph LR
    subgraph GreyNoise API
        direction TB
        Feed[Feed API]
    end

    subgraph OpenCTI
        direction LR
        Identity[Identity - GreyNoise]
        IP[IPv4-Addr Observable]
        Indicator[Indicator]
        Vulnerability[Vulnerability]
    end

    Feed --> Identity
    Feed --> IP
    Feed --> Indicator
    Feed --> Vulnerability
    Indicator -- based-on --> IP
    Indicator -- indicates --> Vulnerability
```

### Entity Mapping

| GreyNoise Data       | OpenCTI Entity      | Description                                      |
|----------------------|---------------------|--------------------------------------------------|
| IP Address           | IPv4-Addr           | IP observable with GreyNoise metadata            |
| IP Address           | Indicator           | STIX pattern `[ipv4-addr:value = '...']`         |
| CVE Tags             | Vulnerability       | Associated CVEs from GreyNoise tags              |
| Classification       | Labels              | benign, malicious, unknown                       |

### Processing Details

For each IP in the GreyNoise feed:

1. **Observable**: IPv4-Addr with GreyNoise context
2. **Indicator**: Created with STIX pattern
3. **Vulnerability**: Created when GreyNoise tag indicates CVE exploitation
4. **Relationship**: Indicator → `indicates` → Vulnerability

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

Ensure the GreyNoise API is reachable from your OpenCTI system. For API issues, contact [support@greynoise.io](mailto:support@greynoise.io).

## Additional information

- **Subscription Required**: GreyNoise Feed access requires a paid subscription
- **Enrichment**: Use with GreyNoise enrichment connector for detailed IP context
- **Classifications**: IPs are classified as benign, malicious, or unknown
- **Reference**: [GreyNoise](https://www.greynoise.io/)
