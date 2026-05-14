# OpenCTI Microsoft Defender Intel Synchronizer Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

The Microsoft Defender Intel Synchronizer connector synchronizes OpenCTI TAXII collections with Microsoft Defender legacy intelligence (maximum 15,000 indicators, most recent first).

## Table of Contents

- [OpenCTI Microsoft Defender Intel Synchronizer Connector](#opencti-microsoft-defender-intel-synchronizer-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Microsoft Entra ID (formerly Azure AD) Application Setup](#microsoft-entra-id-formerly-azure-ad-application-setup)
    - [Configuration variables](#configuration-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
    - [Important Note on Permissions](#important-note-on-permissions)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Data Flow](#data-flow)
    - [Synchronization Process](#synchronization-process)
    - [Available Actions](#available-actions)
  - [Debugging](#debugging)
    - [Common Issues](#common-issues)
  - [Additional information](#additional-information)

## Introduction

This connector enables organizations to synchronize OpenCTI TAXII collections with Microsoft Defender for Endpoint. Unlike the stream-based connector, this synchronizer pulls indicators from TAXII collections at regular intervals.

Key features:
- TAXII collection-based synchronization
- Support for up to 15,000 indicators (Microsoft Defender limit)
- Configurable sync interval
- Support for RBAC group assignment
- Custom notification URLs for Block/Warn actions

## Installation

### Requirements

- OpenCTI Platform >= 6.4
- Microsoft Entra ID (formerly Azure AD) Application with appropriate permissions
- Microsoft Defender for Endpoint license
- OpenCTI user with "Access data sharing → Manage data sharing" capability

### Microsoft Entra ID (formerly Azure AD) Application Setup

If you don't know how to get the `tenant_id`, `client_id`, and `client_secret` information, here's a screenshot to
help.
![Sentinel_variables](doc/sentinel_info_variables.png)

It's also important to define the necessary permissions in Microsoft Entra ID (formerly Azure AD) for the connector to work.

In the Entra portal, set:

Home > Application registrations > OpenCTI (your app name) > API permissions

The connector requires the following application permissions for Microsoft Defender XDR / Microsoft 365 Defender APIs:

| Permission                 | Purpose                                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `Ti.ReadWrite.All`         | Create, update, and delete indicators.                                                                          |
| `Indicators.ReadWrite.All` | (Equivalent to above; exact name depends on portal version.)                                                    |
| `Score.Read.All`           | Required for RBAC-scoped synchronization — used to list device groups via `/api/exposureScore/ByMachineGroups`. |

After adding these permissions, click Grant admin consent.

You will then be able to view the data (indicators) in:
Home > Microsoft Defender > Settings > Endpoints > Indicators

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `opencti` | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------------|------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `connector`       | config.yml                    | Docker environment variable             | Default | Mandatory | Example                                | Description                                                                            |
|-----------------------------|-------------------------------|-----------------------------------------|---------|-----------|----------------------------------------|----------------------------------------------------------------------------------------|
| ID                          | `id`                          | `CONNECTOR_ID`                          | /       | Yes       | `fe418972-1b42-42c9-a665-91544c1a9939` | A unique `UUIDv4` identifier for this connector instance.                              |
| Name                        | `name`                        | `CONNECTOR_NAME`                        | /       | Yes       | `Microsoft Defender Intel Synchronizer`                   | Full name of the connector : `Microsoft Defender Intel Synchronizer`.                                     |
| Scope                       | `scope`                       | `CONNECTOR_SCOPE`                       | /       | Yes       | `sentinel`                             | Must be `sentinel`, not used in this connector.                                        |
| Log Level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | /       | Yes       | `error`                                | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

### Connector extra parameters environment variables

| Parameter                    | config.yml                                                  | Docker environment variable                                 | Default                                    | Mandatory | Description                                                               |
| ---------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------ | --------- | ------------------------------------------------------------------------- |
| Tenant ID                    | `microsoft_defender_intel_synchronizer.tenant_id`           | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TENANT_ID`           |                                            | Yes       | Microsoft Entra ID (formerly Azure AD) Tenant ID.                         |
| Client ID                    | `microsoft_defender_intel_synchronizer.client_id`           | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_ID`           |                                            | Yes       | Microsoft Entra ID (formerly Azure AD) Application Client ID.             |
| Client Secret                | `microsoft_defender_intel_synchronizer.client_secret`       | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_SECRET`       |                                            | Yes       | Microsoft Entra ID (formerly Azure AD) Application Client Secret.         |
| Login URL                    | `microsoft_defender_intel_synchronizer.login_url`           | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_LOGIN_URL`           | `https://login.microsoftonline.com`        | No        | Microsoft login URL.                                                      |
| API Base URL                 | `microsoft_defender_intel_synchronizer.base_url`            | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_BASE_URL`            | `https://api.securitycenter.microsoft.com` | No        | Microsoft Defender API base URL.                                          |
| Resource Path                | `microsoft_defender_intel_synchronizer.resource_path`       | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RESOURCE_PATH`       | `/api/indicators`                          | No        | API endpoint path for indicators.                                         |
| Expire Time                  | `microsoft_defender_intel_synchronizer.expire_time`         | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EXPIRE_TIME`         | 30                                         | Yes       | Days before indicators expire in Defender.                                |
| Action                       | `microsoft_defender_intel_synchronizer.action`              | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_ACTION`              | `Audit`                                    | No        | Default action: `Allowed`, `Audit`, `Block`, `BlockAndRemediate`, `Warn`. |
| Passive Only                 | `microsoft_defender_intel_synchronizer.passive_only`        | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_PASSIVE_ONLY`        | false                                      | No        | Silent/audit mode without user notification.                              |
| TAXII Collections            | `microsoft_defender_intel_synchronizer.taxii_collections`   | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TAXII_COLLECTIONS`   |                                            | Yes       | Comma-separated list of TAXII collection IDs.                             |
| Interval                     | `microsoft_defender_intel_synchronizer.interval`            | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_INTERVAL`            | 300                                        | No        | Sync interval in seconds.                                                 |
| Recommended Actions          | `microsoft_defender_intel_synchronizer.recommended_actions` | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RECOMMENDED_ACTIONS` |                                            | No        | Recommended actions for TI indicator alerts.                              |
| RBAC Group Names             | `microsoft_defender_intel_synchronizer.rbac_group_names`    | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES`    | []                                         | No        | JSON array of RBAC group names.                                           |
| Educate URL                  | `microsoft_defender_intel_synchronizer.educate_url`         | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EDUCATE_URL`         |                                            | No        | Custom notification URL for Block/Warn actions.                           |
| Update Only Owned Indicators | `microsoft_defender_intel_synchronizer.update_only_owned`   | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_UPDATE_ONLY_OWNED`   | `true`                                     | No        | Controls whether the connector will manage only owned indicators.         |
| Max Indicators               | `microsoft_defender_intel_synchronizer.max_indicators`      | `MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_MAX_INDICATORS`      | 15000                                      | No        | Maximum number of indicators to sync (Defender limit is 15,000).          |

`taxii_collections` supports:

- **Simple list:** `COLL1,COLL2` (or `["COLL1","COLL2"]`) to use global defaults.
- **Advanced map:** JSON (or YAML) object where each key is a collection ID and the value is a policy override, e.g.:

```json
  {
    "COLL1": { "action": "Block", "expire_time": 30, "recommended_actions": "Block immediately", "educate_url": "https://support.example.com", "rbac_group_names": ["Linux","Servers"], "max_indicators": 1000 },
    "COLL2": {}
  }
```

Supported keys: `action`, `expire_time`, `recommended_actions`, `educate_url`, `rbac_group_names`, and `max_indicators`.
Per-collection overrides always take precedence over global settings.

### Important Note on Permissions

The user impersonating this connector **must** have the capability "Access data sharing → Manage data sharing" in OpenCTI. Without this permission, the connector will fail with a `FORBIDDEN_ACCESS` error, and you will see a message similar to:

```txt
ValueError: {'name': 'FORBIDDEN_ACCESS', 'error_message': 'You are not allowed to do this.'}
```

Please ensure the connector's user has this permission assigned, in addition to the usual required permissions.

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-microsoft-defender-intel-synchronizer:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-microsoft-defender-intel-synchronizer:
    image: opencti/connector-microsoft-defender-intel-synchronizer:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Microsoft Defender Intel Synchronizer
      - CONNECTOR_SCOPE=sentinel
      - CONNECTOR_LOG_LEVEL=info
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TENANT_ID=ChangeMe
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_ID=ChangeMe
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_SECRET=ChangeMe
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EXPIRE_TIME=30
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TAXII_COLLECTIONS=collection1,collection2
      - MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_INTERVAL=300
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

1. Create TAXII collections in OpenCTI with the indicators you want to sync
2. Note the TAXII collection IDs
3. Set up Microsoft Entra ID (formerly Azure AD) Application with `Ti.ReadWrite.All` permissions
4. Configure the connector with the TAXII collection IDs
5. Start the connector

The connector will pull indicators from TAXII collections at the configured interval.

## Behavior

The connector polls TAXII collections at regular intervals and synchronizes indicators to Microsoft Defender.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        TAXII[TAXII Collections]
        Indicators[Indicators]
    end

    subgraph Connector
        direction LR
        Poll[Poll TAXII]
        Sync[Sync to Defender]
    end

    subgraph Microsoft
        direction TB
        API[Defender API]
        TI[Threat Intelligence]
    end

    TAXII --> Indicators
    Indicators --> Poll
    Poll --> Sync
    Sync --> API
    API --> TI
```

### Synchronization Process

| Step | Description                                              |
|------|----------------------------------------------------------|
| 1    | Poll TAXII collections at configured interval            |
| 2    | Retrieve up to 15,000 most recent indicators             |
| 3    | Convert indicators to Defender format                    |
| 4    | Sync to Microsoft Defender (create/update/delete)        |

### Available Actions

| Action           | Description                                              |
|------------------|----------------------------------------------------------|
| Allowed          | Explicitly allow the indicator                           |
| Audit            | Log only, no action                                      |
| Block            | Block the indicator                                      |
| BlockAndRemediate| Block and remediate                                      |
| Warn             | Generate warning without blocking                        |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                                     | Solution                                              |
|-------------------------------------------|-------------------------------------------------------|
| FORBIDDEN_ACCESS error                    | Ensure user has "Manage data sharing" capability      |
| Authentication errors                     | Verify tenant_id, client_id, and client_secret        |
| Permission denied                         | Ensure Ti.ReadWrite.All permission is granted         |
| Indicator not appearing                   | Wait a few minutes; sync is not instant               |
| 401 Unauthorized during RBAC group lookup | Ensure the application has the `Score.Read.All` permission and admin consent has been granted. Without this permission, the `/api/exposureScore/ByMachineGroups` endpoint cannot be accessed, and RBAC-scoped indicator synchronization will fail. |

## Additional information

- **Indicator Limit**: Maximum 15,000 indicators, most recent first
- **Sync Delay**: Indicators may take a few minutes to appear in Microsoft Defender
- **RBAC Groups**: Use JSON array format: `["Group1", "Group2"]`
- **Educate URL**: Custom support URL shown during Block/Warn actions
- **Permission Required**: OpenCTI user must have "Access data sharing → Manage data sharing" capability
