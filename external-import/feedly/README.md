# OpenCTI Feedly Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The Feedly connector imports threat intelligence from Feedly AI-powered news feeds into OpenCTI.

## Table of Contents

- [OpenCTI Feedly Connector](#opencti-feedly-connector)
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

Feedly is an AI-powered news aggregator that helps security teams track threat intelligence from various sources. This connector imports articles from configured Feedly streams, extracting threat intelligence entities and creating reports in OpenCTI.

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Feedly account with API access
- Feedly API key

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-feedly:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-feedly:
    image: opencti/connector-feedly:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Feedly
      - CONNECTOR_SCOPE=feedly
      - CONNECTOR_LOG_LEVEL=error
      - FEEDLY_INTERVAL=60
      - FEEDLY_STREAM_IDS=enterprise/your-org/category/threat-intel
      - FEEDLY_DAYS_TO_BACK_FILL=7
      - FEEDLY_API_KEY=ChangeMe
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

The connector runs automatically at the interval defined by `FEEDLY_INTERVAL`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new sync.

## Behavior

The connector fetches articles from Feedly streams and extracts threat intelligence entities.

### Data Flow

```mermaid
graph LR
    subgraph Feedly
        direction TB
        Stream[Stream]
        Article[Article]
        Entity[Extracted Entities]
    end

    subgraph OpenCTI
        direction LR
        Report[Report]
        Observable[Observable]
        ThreatActor[Threat Actor]
        Malware[Malware]
        Vulnerability[Vulnerability]
    end

    Stream --> Article
    Article --> Report
    Entity --> Observable
    Entity --> ThreatActor
    Entity --> Malware
    Entity --> Vulnerability
```

### Entity Mapping

| Feedly Data          | OpenCTI Entity      | Description                                      |
|----------------------|---------------------|--------------------------------------------------|
| Article              | Report              | News article as report                           |
| CVE Entity           | Vulnerability       | Extracted CVE references                         |
| Threat Actor Entity  | Threat-Actor        | Mentioned threat actors                          |
| Malware Entity       | Malware             | Referenced malware                               |
| IOC Entity           | Observable          | Extracted indicators                             |

### Getting Stream IDs

Stream IDs can be found in Feedly:

1. Navigate to your feed or board
2. Click on the settings icon
3. Look for the "Stream ID" in the URL or settings

Example stream ID formats:
- `enterprise/your-org/category/threat-intel`
- `user/your-user-id/category/security`
- `feed/https://example.com/feed.xml`

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

## Additional information

- **API Key**: Generate at [Feedly API](https://feedly.com/i/team/api)
- **AI Entities**: Feedly's AI extracts entities from articles automatically
- **Multiple Streams**: Configure multiple streams separated by commas
- **Reference**: [Feedly for Threat Intel](https://feedly.com/threat-intelligence)
