# OpenCTI External Ingestion Connector for MokN

## Table of Contents

- [OpenCTI External Ingestion Connector for MokN](#opencti-external-ingestion-connector-for-mokn)
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
  - [Documentation](#documentation)

## Introduction

This connector for OpenCTI ingests contextualized threat intelligence from the MokN Bait platform. It processes login attempts from bait systems and creates STIX2 objects including indicators, observables, sightings, and incidents based on threat level and credential status.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- Python 3.11+
- `pycti` library matching your OpenCTI version
- `connectors-sdk` (installed via `requirements.txt`)

## Configuration variables

Configuration options are set in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | `UUIDv4`        | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | `EXTERNAL_IMPORT` | Yes       | Should always be `EXTERNAL_IMPORT`.                                                      |
| Connector Name  | name       | `CONNECTOR_NAME`            | `MokN`          | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | `mokn`          | Yes       | The scope or type of data the connector is importing.                                    |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | `info`          | Yes       | Determines the verbosity of the logs (`debug`, `info`, `warn`, or `error`).              |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT1H`           | No        | Determines the time interval between each launch of the connector.  |

### Connector extra parameters environment variables

| Parameter         | config.yml            | Docker environment variable   | Default | Mandatory | Description                                                     |
|-------------------|-----------------------|-------------------------------|---------|-----------|-----------------------------------------------------------------|
| MokN Console URL  | `mokn_console_url`    | `MOKN_CONSOLE_URL`            |         | Yes       | The base URL of your MokN console.                              |
| MokN API Key      | `mokn_api_key`        | `MOKN_API_KEY`                |         | Yes       | Your API key for the MokN platform.                             |
| MokN TLP Level    | `mokn_tlp_level`      | `MOKN_TLP_LEVEL`              | `amber` | No        | TLP level for the data (`clear`, `white`, `green`, `amber`, `amber+strict`, `red`). |
| First Run Days    | `mokn_first_run_days_back` | `MOKN_FIRST_RUN_DAYS_BACK` | `30`    | No        | Number of days to retrieve on first execution.                  |

## Deployment

### Docker Deployment

1.  **Set pycti version**: Ensure the `pycti` version in `requirements.txt` matches your OpenCTI version (e.g., `pycti==6.9.9`).
2.  **Build Docker Image**:
    ```shell
    docker build . -t opencti-connector-mokn:latest
    ```
3.  **Configure `docker-compose.yml`**: Update the environment variables in `docker-compose.yml` with your specific settings.
4.  **Run the container**:
    ```shell
    docker-compose up -d
    ```

### Manual Deployment

1.  **Create `config.yml`**: Create a `config.yml` file based on `config.yml.sample`.
2.  **Update Configuration**: Replace the placeholder values in `config.yml` with your environment's configurations.
3.  **Install Dependencies** (preferably in a virtual environment):
    ```shell
    pip install -r src/requirements.txt
    ```
4.  **Run the connector**:
    ```shell
    python3 src/main.py
    ```

## Usage

Once installed and configured, the connector runs automatically at the specified interval. To trigger a manual run:

1.  Navigate to `Data` > `Ingestion` in OpenCTI.
2.  Find the `MokN` connector.
3.  Click the refresh button to reset the state and initiate a new data fetch.

## Behavior

The connector fetches login attempt data from the MokN Bait API and processes it based on threat level and credential status:

### Threat Level Processing

#### HIGH Threat
- **IPv4-Addr Observable**: The attacking IP address
- **Indicator**: STIX indicator with pattern `[ipv4-addr:value = 'x.x.x.x']`
  - Score: 80 (or 100 if valid credentials detected)
  - Confidence: 80
  - Validity: 7 days from attempt date
  - Labels: `mokn:high`, plus `mokn:valid_credentials` if applicable
- **Relationship**: `based-on` relationship linking Indicator to Observable
- **Sighting**: One sighting per login attempt with timestamp
- **UserAccount Observable**: Created if the username exists in the target system
  - Linked to the Indicator via `based-on` relationship

#### MEDIUM Threat
- **IPv4-Addr Observable**: The attacking IP address (no indicator created)
- **UserAccount Observable**: Created if the username exists in the target system

#### Valid Credentials (Status = 1)
When successful authentication is detected on the bait:
- **Incident**: "Valid Credentials Compromise" incident
  - Type: `compromise`
  - Severity: `high`
  - Description includes username, IP, and timestamp
  - Label: `mokn:valid_credentials`
- **Relationships**: Incident linked to both IP and UserAccount observables
- **Indicator score upgraded to 100** (instead of 80)

### Data Synchronization
- **Incremental**: Only fetches login attempts since last execution
- **First Run**: Retrieves data from the last 30 days (configurable)
- **Deduplication**: Uses deterministic IDs to prevent duplicate indicators
- **Pagination**: Automatically handles paginated API responses

## Debugging

To debug the connector, set `CONNECTOR_LOG_LEVEL` to `debug` in your configuration (`docker-compose.yml` or `config.yml`). This will provide verbose logs to help identify and resolve issues.

## Troubleshooting

### Common issues

1. **No data ingested**
   **Cause**: No new login attempts since last run or filtering window too narrow.  
   **Solution**: Increase `MOKN_FIRST_RUN_DAYS_BACK` and verify `last_timestamp` in connector state.

2. **API errors (4xx/5xx)**
   **Cause**: Invalid API key or console URL, or temporary server issue.  
   **Solution**: Check `MOKN_API_KEY`, `MOKN_CONSOLE_URL`, and retry.

## Additional information

### STIX Objects Created

This connector creates the following STIX2 objects:

**Entities:**
- `Identity`: MokN organization (connector author)
- `Indicator`: Malicious IP indicators (HIGH threat only)
- `Incident`: Credential compromise incidents (when valid credentials are used)
- `Relationship`: Links between indicators, observables, and incidents

**Observables:**
- `IPv4-Addr`: IP addresses from login attempts (HIGH and MEDIUM threats)
- `UserAccount`: Compromised or targeted usernames (when user exists)

**Sighting:**
- `Sighting`: Observations of indicators (one per HIGH threat login attempt)

### Labels
- `mokn:high`: HIGH threat level attacks
- `mokn:medium`: MEDIUM threat level attacks
- `mokn:valid_credentials`: Attacks with valid credentials

### Best Practices
- Run this connector with a dedicated user account in OpenCTI with appropriate permissions
- Configure TLP marking according to your data sharing policy
- Adjust `CONNECTOR_DURATION_PERIOD` based on your MokN attack volume

## Documentation

For detailed information about the data processing logic and STIX object creation, see [SCHEMA.md](SCHEMA.md).

This document includes:
- Complete data flow diagram
- Processing logic for each threat level
- STIX object creation details
- Deduplication strategy
- Login attempt status codes reference