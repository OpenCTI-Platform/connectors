# OpenCTI Intel 471 Connector (Legacy)

> ⚠️ **DEPRECATED**: This is the legacy version of the connector. Please use [OpenCTI Intel 471 Connector v2](../intel471_v2) for new deployments.

The Intel 471 connector imports threat intelligence from Intel 471's Titan cybercrime intelligence platform into OpenCTI.

| Status           | Date | Comment |
|------------------|------|---------|
| Partner Verified | -    | -       |

## Table of Contents

- [OpenCTI Intel 471 Connector (Legacy)](#opencti-intel-471-connector-legacy)
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

Intel 471 delivers structured technical and non-technical data and intelligence on cyber threats. This connector ingests STIX 2.1 objects from Intel 471's Titan cybercrime intelligence platform.

The connector runs four data streams:

| Stream                    | Description                                          | Produced Objects                                        |
|---------------------------|------------------------------------------------------|--------------------------------------------------------|
| Intel471IndicatorsStream  | Fetches malware indicators from `/indicators` API    | Indicator, Malware, URL/IPv4/File Observables          |
| Intel471YARAStream        | Fetches YARA rules from `/yara` API                  | Indicator (YARA), Malware                              |
| Intel471IOCsStream        | Fetches IOCs from `/iocs` API                        | Indicator, Report, URL/Domain/IPv4/File Observables    |
| Intel471CVEsStream        | Fetches CVE reports from `/cve/reports` API          | Vulnerability                                          |

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Intel 471 account with API credentials (paid subscription required)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter         | config.yml      | Docker environment variable   | Default   | Mandatory | Description                                                                 |
|-------------------|-----------------|-------------------------------|-----------|-----------|-----------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`                |           | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name    | name            | `CONNECTOR_NAME`              | Intel 471 | No        | Name of the connector.                                                      |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`             | intel471  | No        | The scope or type of data the connector is importing.                       |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`         | info      | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.  |

### Connector extra parameters environment variables

| Parameter                         | config.yml                   | Docker environment variable              | Default | Mandatory | Description                                                                 |
|-----------------------------------|------------------------------|------------------------------------------|---------|-----------|-----------------------------------------------------------------------------|
| API Username                      | api_username                 | `INTEL471_API_USERNAME`                  |         | Yes       | Titan API username.                                                         |
| API Key                           | api_key                      | `INTEL471_API_KEY`                       |         | Yes       | Titan API key.                                                              |
| Indicators Interval               | interval_indicators          | `INTEL471_INTERVAL_INDICATORS`           |         | No        | Minutes between indicator fetches. Leave empty to disable.                  |
| Indicators Initial History        | initial_history_indicators   | `INTEL471_INITIAL_HISTORY_INDICATORS`    |         | No        | Epoch milliseconds for initial fetch start date.                            |
| IOCs Interval                     | interval_iocs                | `INTEL471_INTERVAL_IOCS`                 |         | No        | Minutes between IOC fetches. Leave empty to disable.                        |
| IOCs Initial History              | initial_history_iocs         | `INTEL471_INITIAL_HISTORY_IOCS`          |         | No        | Epoch milliseconds for initial fetch start date.                            |
| CVEs Interval                     | interval_cves                | `INTEL471_INTERVAL_CVES`                 |         | No        | Minutes between CVE report fetches. Leave empty to disable.                 |
| CVEs Initial History              | initial_history_cves         | `INTEL471_INITIAL_HISTORY_CVES`          |         | No        | Epoch milliseconds for initial fetch start date.                            |
| YARA Interval                     | interval_yara                | `INTEL471_INTERVAL_YARA`                 |         | No        | Minutes between YARA rule fetches. Leave empty to disable.                  |
| YARA Initial History              | initial_history_yara         | `INTEL471_INITIAL_HISTORY_YARA`          |         | No        | Epoch milliseconds for initial fetch start date.                            |
| Proxy                             | proxy                        | `INTEL471_PROXY`                         |         | No        | Optional proxy URL (e.g., `http://user:pass@localhost:3128`).               |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-intel471:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-intel471:
    image: opencti/connector-intel471:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Intel 471
      - CONNECTOR_SCOPE=intel471
      - CONNECTOR_LOG_LEVEL=info
      - INTEL471_API_USERNAME=ChangeMe
      - INTEL471_API_KEY=ChangeMe
      - INTEL471_INTERVAL_INDICATORS=60
      - INTEL471_INTERVAL_IOCS=60
      - INTEL471_INTERVAL_CVES=60
      - INTEL471_INTERVAL_YARA=60
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

Navigate to **Data → Connectors → Intel471** to observe completed and in-progress work items. Data appears after configured intervals when new data is available in Titan.

**View imported data:**
- **Indicators**: Observations → Indicators
- **Malware**: Arsenal → Malwares
- **Reports**: Analysis → Reports
- **CVEs**: Arsenal → Vulnerabilities

## Behavior

The connector fetches data from Intel 471's Titan API across multiple streams.

### Data Flow

```mermaid
graph LR
    subgraph Intel 471 Titan
        direction TB
        Indicators[/indicators API]
        IOCs[/iocs API]
        CVEs[/cve/reports API]
        YARA[/yara API]
    end

    subgraph OpenCTI
        direction LR
        Indicator[Indicator]
        Observable[Observable]
        Malware[Malware]
        Report[Report]
        Vulnerability[Vulnerability]
    end

    Indicators --> Indicator
    Indicators --> Malware
    Indicators --> Observable
    IOCs --> Report
    IOCs --> Indicator
    CVEs --> Vulnerability
    YARA --> Indicator
```

### Entity Mapping

| Intel 471 Data       | OpenCTI Entity      | Description                                      |
|----------------------|---------------------|--------------------------------------------------|
| Malware Indicator    | Indicator           | IOC with pattern                                 |
| Malware Family       | Malware             | Malware family SDO                               |
| IOC                  | Report + Indicator  | Intelligence report with IOCs                    |
| CVE Report           | Vulnerability       | CVE vulnerability                                |
| YARA Rule            | Indicator (YARA)    | YARA detection rule                              |
| URL/Domain/IP/Hash   | Observable          | Technical observables                            |

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

## Additional information

- **Paid Subscription**: Intel 471 API access requires a paid subscription
- **Stream Control**: Each stream can be independently enabled/disabled
- **Pro Tip**: Create a dedicated API token for the connector to track created objects
- **Contact**: For API access, contact sales@intel471.com
- **Reference**: [Intel 471](https://www.intel471.com)
