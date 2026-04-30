# OpenCTI Microsoft Sentinel Intel Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

The Microsoft Sentinel Intel connector streams OpenCTI indicators to Microsoft Sentinel using the Upload Indicators API for threat intelligence integration.

## Table of Contents

- [OpenCTI Microsoft Sentinel Intel Connector](#opencti-microsoft-sentinel-intel-connector)
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

This connector enables organizations to create, update, and delete threat indicators from OpenCTI to Microsoft Sentinel. It uses the modern Upload Indicators API for reliable integration.

Key features:
- Real-time synchronization of indicators to Microsoft Sentinel
- Support for create, update, and delete operations
- Managed identity or app registration authentication
- Configurable source system and extra labels
- STIX bundle format for comprehensive threat intelligence

## Installation

### Requirements

- OpenCTI Platform >= 7.260430.0
- Azure subscription with Microsoft Sentinel
- Azure AD Application or Managed Identity with appropriate permissions

### Azure AD Application Setup

1. Register an application in Azure AD (Entra portal)
2. Note the `tenant_id`, `client_id`, and `client_secret`
3. Configure API permissions: **ThreatIndicators.ReadWrite.OwnedBy**
4. In the Log Analytics Workspace, add **Microsoft Sentinel Contributor** role to the application

![Sentinel Variables](./doc/sentinel_info_variables.png)
![Sentinel Permissions](./doc/permission_mandatory.png)

View indicators in: **Microsoft Sentinel > Threat Intelligence > Indicators**

For more information:
- [Microsoft Connect Threat Intelligence](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api)
- [Microsoft Security Authorization](https://learn.microsoft.com/en-us/graph/security-authorization)

## Configuration

Configuration parameters can be provided in either **`config.yml`** file, **`.env`** file or directly as **environment variables** (e.g. from **`docker-compose.yml`** for Docker deployments).

Priority: **YAML > .env > environment > defaults**.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-microsoft-sentinel-intel:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-microsoft-sentinel-intel:
    image: opencti/connector-microsoft-sentinel-intel:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Microsoft Sentinel Intel
      - CONNECTOR_SCOPE=sentinel
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_LIVE_STREAM_ID=ChangeMe
      - CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true
      - CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES=true
      - MICROSOFT_SENTINEL_INTEL_TENANT_ID=ChangeMe
      - MICROSOFT_SENTINEL_INTEL_CLIENT_ID=ChangeMe
      - MICROSOFT_SENTINEL_INTEL_CLIENT_SECRET=ChangeMe
      - MICROSOFT_SENTINEL_INTEL_WORKSPACE_ID=ChangeMe
      - MICROSOFT_SENTINEL_INTEL_WORKSPACE_NAME=ChangeMe
      - MICROSOFT_SENTINEL_INTEL_SUBSCRIPTION_ID=ChangeMe
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

1. Set up Azure AD Application with required permissions
2. Assign Microsoft Sentinel Contributor role in Log Analytics Workspace
3. Create a Live Stream in OpenCTI (Data Management -> Data Sharing -> Live Streams)
4. Configure the stream to include indicators
5. Start the connector

## Behavior

The connector listens to OpenCTI live stream events and manages indicators in Microsoft Sentinel.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        Stream[Live Stream]
        Indicators[Indicator Events]
    end

    subgraph Connector
        direction LR
        Listen[Event Listener]
        Convert[Convert to STIX]
    end

    subgraph Azure
        direction TB
        API[Upload API]
        Sentinel[Microsoft Sentinel]
    end

    Stream --> Indicators
    Indicators --> Listen
    Listen --> Convert
    Convert --> API
    API --> Sentinel
```

### Event Processing

| Event Type | Action                                       |
|------------|----------------------------------------------|
| create     | Creates indicator in Microsoft Sentinel      |
| update     | Updates indicator in Microsoft Sentinel      |
| delete     | Removes indicator via Management API         |

### Deletion Requirements

For deletion to work properly, the following must be configured:
- `source_system`
- `workspace_name`
- `subscription_id`

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                          | Solution                                              |
|--------------------------------|-------------------------------------------------------|
| Permission denied              | Ensure Microsoft Sentinel Contributor role is assigned |
| Role not propagated            | Wait for role assignment to propagate                 |
| Indicator not appearing        | Wait a few minutes; sync is not instant               |
| Deletion not working           | Verify source_system, workspace_name, subscription_id |

## Additional information

- **Role Propagation**: Role assignments on Log Analytics Workspace can take time to propagate
- **Authentication**: Managed identity is recommended over app registration
- **STIX Bundles**: Indicators are sent as STIX bundles to preserve threat intelligence context
- **Extra Labels**: Add comma-separated labels to all indicators sent to Sentinel
- **Delete Extensions**: Set to `true` to remove OpenCTI-specific extensions from bundles
