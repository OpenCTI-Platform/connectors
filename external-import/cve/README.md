# OpenCTI CVE Connector

The CVE connector imports Common Vulnerabilities and Exposures (CVE) data from the NIST National Vulnerability Database (NVD) into OpenCTI.

| Status            | Date       | Comment |
|-------------------|------------|---------|
| Filigran Verified | 2023-12-15 | -       |

## Table of Contents

- [OpenCTI CVE Connector](#opencti-cve-connector)
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

The National Vulnerability Database (NVD) is the U.S. government repository of standards-based vulnerability management data. This connector retrieves CVE (Common Vulnerabilities and Exposures) data from the NVD API and imports it into OpenCTI as Vulnerability entities.

The connector supports both incremental updates (maintaining data since last run) and historical import (pulling all CVEs from a specified year).

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- NVD API key (required - request at [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key))

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter         | config.yml      | Docker environment variable   | Default                                  | Mandatory | Description                                                                 |
|-------------------|-----------------|-------------------------------|------------------------------------------|-----------|-----------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`                |                                          | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name    | name            | `CONNECTOR_NAME`              | Common Vulnerabilities and Exposures     | No        | Name of the connector.                                                      |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`             | cve                                      | No        | The scope or type of data the connector is importing.                       |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`         | error                                    | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.  |

### Connector extra parameters environment variables

| Parameter          | config.yml           | Docker environment variable | Default                                      | Mandatory | Description                                                                 |
|--------------------|----------------------|-----------------------------|----------------------------------------------|-----------|-----------------------------------------------------------------------------|
| API Key            | cve.api_key          | `CVE_API_KEY`               |                                              | Yes       | Your NVD API key.                                                           |
| Base URL           | cve.base_url         | `CVE_BASE_URL`              | https://services.nvd.nist.gov/rest/json/cves | No        | NVD API endpoint URL.                                                       |
| Interval           | cve.interval         | `CVE_INTERVAL`              | 6                                            | No        | Interval in hours between checks. Minimum 2 hours recommended by NIST.      |
| Max Date Range     | cve.max_date_range   | `CVE_MAX_DATE_RANGE`        | 120                                          | No        | Maximum days per API query. Maximum 120 days.                               |
| Maintain Data      | cve.maintain_data    | `CVE_MAINTAIN_DATA`         | true                                         | No        | Import CVEs from last run to current time (incremental updates).            |
| Pull History       | cve.pull_history     | `CVE_PULL_HISTORY`          | false                                        | No        | Import all CVEs from `history_start_year`. Requires `history_start_year`.   |
| History Start Year | cve.history_start_year | `CVE_HISTORY_START_YEAR`  | 2019                                         | No        | Required if `pull_history=true`. Minimum 2019 (CVSS v3.1 release).          |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-cve:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-cve:
    image: opencti/connector-cve:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Common Vulnerabilities and Exposures
      - CONNECTOR_SCOPE=cve
      - CONNECTOR_LOG_LEVEL=error
      - CVE_API_KEY=ChangeMe
      - CVE_INTERVAL=6 # In hours, minimum 2 recommended by NIST
      # - CVE_BASE_URL=https://services.nvd.nist.gov/rest/json/cves
      # - CVE_MAX_DATE_RANGE=120
      # - CVE_MAINTAIN_DATA=true
      # - CVE_PULL_HISTORY=false
      # - CVE_HISTORY_START_YEAR=2019
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
python3 -m __main__
```

## Usage

The connector runs automatically at the interval defined by `CVE_INTERVAL`. To force an immediate run:

**Data Management → Ingestion → Connectors**

Find the connector and click the refresh button to reset the state and trigger a new sync.

## Behavior

The connector fetches CVE data from the NVD API and converts it to STIX Vulnerability objects.

### Data Flow

```mermaid
graph LR
    subgraph NVD API
        direction TB
        CVE[CVE Data]
    end

    subgraph OpenCTI
        direction LR
        Vulnerability[Vulnerability]
        ExternalRef[External Reference]
    end

    CVE --> Vulnerability
    CVE --> ExternalRef
```

### Entity Mapping

| NVD CVE Data         | OpenCTI Entity/Property | Description                                      |
|----------------------|-------------------------|--------------------------------------------------|
| CVE ID               | Vulnerability.name      | CVE identifier (e.g., CVE-2021-44228)            |
| Description          | Vulnerability.description | CVE description                                |
| Published Date       | Vulnerability.created   | Date CVE was published                           |
| Last Modified        | Vulnerability.modified  | Last modification date                           |
| CVSS v3.1 Score      | Vulnerability.x_opencti_cvss_base_score | CVSS base score              |
| CVSS v3.1 Severity   | Vulnerability.x_opencti_cvss_base_severity | CRITICAL/HIGH/MEDIUM/LOW |
| CVSS v3.1 Vector     | Vulnerability.x_opencti_cvss_attack_vector | Attack vector            |
| CWE IDs              | Labels                  | Weakness classifications                         |
| References           | External References     | Links to advisories and patches                  |

### Operating Modes

1. **Incremental Updates** (`maintain_data=true`):
   - Default mode
   - Imports CVEs modified since the last run
   - Keeps vulnerability data up-to-date

2. **Historical Import** (`pull_history=true`):
   - Imports all CVEs from specified year to present
   - Useful for initial population
   - Requires `history_start_year` (minimum 2019)

### Processing Details

- **CVSS v3.1**: Connector uses CVSS v3.1 scores (available from 2019+)
- **Rate Limiting**: NVD API has rate limits; connector handles pagination
- **Date Range**: Maximum 120-day range per API query
- **API Key Required**: Unauthenticated requests are heavily rate-limited

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- API request/response details
- CVE processing progress
- STIX conversion details

## Additional information

- **API Key**: Required for reasonable rate limits. Request at [NVD](https://nvd.nist.gov/developers/request-an-api-key)
- **Rate Limits**: With API key: 50 requests/30 seconds. Without: 5 requests/30 seconds
- **CVSS v3.1**: Minimum start year is 2019 (CVSS v3.1 release date)
- **Large Dataset**: NVD contains 200,000+ CVEs; historical import takes significant time
- **Polling Interval**: NIST recommends minimum 2-hour intervals
- **Reference**: [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
