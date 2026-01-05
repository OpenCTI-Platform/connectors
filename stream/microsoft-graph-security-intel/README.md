# OpenCTI Microsoft Graph Security Intel Connector

| Status | Date | Comment |
|--------|------|---------|
| Deprecated | April 2026 | Use Microsoft Sentinel Intel or Microsoft Defender Intel instead |

**WARNING: This connector is deprecated and will be removed in April 2026.**

This connector relies on Microsoft Graph's Threat Intelligence Indicator API (tiIndicator entity), which Microsoft has officially deprecated.

**Please migrate to:**
- **Microsoft Sentinel Intel**: For Azure Sentinel integration
- **Microsoft Defender Intel**: For Microsoft Defender for Endpoint integration

## Table of Contents

- [OpenCTI Microsoft Graph Security Intel Connector](#opencti-microsoft-graph-security-intel-connector)
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

This connector enables organizations to create or delete threat indicators from OpenCTI to Microsoft Sentinel or Microsoft Defender for Endpoint using the Microsoft Graph API Threat Intelligence Indicator.

Key features:
- Real-time synchronization of indicators
- Support for both Azure Sentinel and Microsoft Defender ATP
- Configurable actions and TLP levels
- Support for create, update, and delete operations

## Installation

### Requirements

- OpenCTI Platform >= 6.4
- Azure AD Application with appropriate permissions

### Azure AD Application Setup

1. Register an application in Azure AD
2. Configure API permissions: **ThreatIndicators.ReadWrite.OwnedBy**

![Sentinel Variables](./doc/sentinel_info_variables.png)
![Sentinel Permissions](./doc/permission_mandatory.png)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter                      | config.yml                | Docker environment variable             | Default | Mandatory | Description                                                                    |
|--------------------------------|---------------------------|-----------------------------------------|---------|-----------|--------------------------------------------------------------------------------|
| Connector ID                   | id                        | `CONNECTOR_ID`                          |         | Yes       | A unique `UUIDv4` identifier for this connector instance.                      |
| Connector Name                 | name                      | `CONNECTOR_NAME`                        |         | Yes       | Name of the connector.                                                         |
| Live Stream ID                 | live_stream_id            | `CONNECTOR_LIVE_STREAM_ID`              |         | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.             |
| Live Stream Listen Delete      | live_stream_listen_delete | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | true    | No        | Listen to delete events.                                                       |
| Live Stream No Dependencies    | live_stream_no_dependencies| `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`| true    | No        | Set to `true` unless synchronizing between OpenCTI platforms.                  |
| Log Level                      | log_level                 | `CONNECTOR_LOG_LEVEL`                   | error   | No        | Determines the verbosity of the logs.                                          |

### Connector extra parameters environment variables

| Parameter        | config.yml                                        | Docker environment variable                     | Default                       | Mandatory | Description                                                |
|------------------|---------------------------------------------------|-------------------------------------------------|-------------------------------|-----------|------------------------------------------------------------|
| Tenant ID        | microsoft_graph_security_intel.tenant_id          | `MICROSOFT_GRAPH_SECURITY_INTEL_TENANT_ID`      |                               | Yes       | Azure AD Tenant ID.                                        |
| Client ID        | microsoft_graph_security_intel.client_id          | `MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_ID`      |                               | Yes       | Azure AD Application Client ID.                            |
| Client Secret    | microsoft_graph_security_intel.client_secret      | `MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_SECRET`  |                               | Yes       | Azure AD Application Client Secret.                        |
| Login URL        | microsoft_graph_security_intel.login_url          | `MICROSOFT_GRAPH_SECURITY_INTEL_LOGIN_URL`      | https://login.microsoft.com   | No        | Microsoft login URL.                                       |
| API Base URL     | microsoft_graph_security_intel.base_url           | `MICROSOFT_GRAPH_SECURITY_INTEL_BASE_URL`       | https://graph.microsoft.com   | No        | Microsoft Graph API base URL.                              |
| Resource Path    | microsoft_graph_security_intel.resource_path      | `MICROSOFT_GRAPH_SECURITY_INTEL_RESOURCE_PATH`  | /beta/security/tiIndicators   | No        | API endpoint path for tiIndicators.                        |
| Expire Time      | microsoft_graph_security_intel.expire_time        | `MICROSOFT_GRAPH_SECURITY_INTEL_EXPIRE_TIME`    | 30                            | No        | Days before indicators expire (when no valid_until).       |
| Target Product   | microsoft_graph_security_intel.target_product     | `MICROSOFT_GRAPH_SECURITY_INTEL_TARGET_PRODUCT` | Azure Sentinel                | No        | `Azure Sentinel` or `Microsoft Defender ATP`.              |
| Action           | microsoft_graph_security_intel.action             | `MICROSOFT_GRAPH_SECURITY_INTEL_ACTION`         | Based on score                | No        | Action: `unknown`, `allow`, `block`, `alert`.              |
| TLP Level        | microsoft_graph_security_intel.tlp_level          | `MICROSOFT_GRAPH_SECURITY_INTEL_TLP_LEVEL`      |                               | No        | Override TLP: `unknown`, `white`, `green`, `amber`, `red`. |
| Passive Only     | microsoft_graph_security_intel.passive_only       | `MICROSOFT_GRAPH_SECURITY_INTEL_PASSIVE_ONLY`   | false                         | No        | Silent/audit mode without user notification.               |

## Deployment

### Docker Deployment

```yaml
  connector-microsoft-graph-security-intel:
    image: opencti/connector-microsoft-graph-security-intel:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Microsoft Graph Security Intel
      - CONNECTOR_LIVE_STREAM_ID=ChangeMe
      - MICROSOFT_GRAPH_SECURITY_INTEL_TENANT_ID=ChangeMe
      - MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_ID=ChangeMe
      - MICROSOFT_GRAPH_SECURITY_INTEL_CLIENT_SECRET=ChangeMe
    restart: always
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

1. Set up Azure AD Application with `ThreatIndicators.ReadWrite.OwnedBy` permissions
2. Create a Live Stream in OpenCTI
3. Configure and start the connector

## Behavior

The connector listens to OpenCTI live stream events and manages indicators via Microsoft Graph API.

### Event Processing

| Event Type | Action                                       |
|------------|----------------------------------------------|
| create     | Creates indicator via Graph API              |
| update     | Updates indicator via Graph API              |
| delete     | Removes indicator via Graph API              |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                          | Solution                                              |
|--------------------------------|-------------------------------------------------------|
| Indicator not appearing        | Wait a few minutes; sync is not instant               |
| Email displays as "Other"      | Known behavior for email address indicators           |

## Additional information

**IMPORTANT: Plan migration before April 2026!**

- **For Azure Sentinel**: Use [Microsoft Sentinel Intel](https://github.com/OpenCTI-Platform/connectors/tree/master/stream/microsoft-sentinel-intel)
- **For Microsoft Defender**: Use [Microsoft Defender Intel](https://github.com/OpenCTI-Platform/connectors/tree/master/stream/microsoft-defender-intel)

Resources:
- [Microsoft Graph tiIndicator Documentation](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta)
- [Microsoft Security Authorization](https://learn.microsoft.com/en-us/graph/security-authorization)
