# OpenCTI Microsoft Sentinel Intelligence Connector

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

This OpenCTI connector allows the ability to create, update and delete indicator data from your OpenCTI platform to
Microsoft Sentinel
Microsoft has a detailed guide on how to get started with connecting your threat intelligence platform to Sentinel
found [here](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api).

## Installation

It is recommended to use a managed identity for authentication. It's also possible to use an app registration.
If you don't know how to get the `tenant_id`, `client_id`, and `client_secret` for the app registration information,
here's a screenshot to
help !
![Sentinel_variables](./doc/sentinel_info_variables.png)

It's also important to define the necessary permissions in Sentinel for the connector to work.

In the Azure portal, you need to set :
Home > Application Registration > OpenCTI (your name) > API Permissions
and prioritize the "ThreatIndicators.ReadWrite.OwnedBy" permissions.
![Sentinel_permission](./doc/permission_mandatory.png)
You will then be able to view the data (indicators) in :
Home > Microsoft Sentinel > OpenCTI (Your Name) > Threat Indicators

For more information, visit:

- [Microsoft Security-Authorization](https://learn.microsoft.com/en-us/graph/security-authorization)
- [Microsoft Connect-Threat-Intelligence-Tip](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip)

Another interesting link:

- [Microsoft Sentinel-Threat-Intelligence](https://learn.microsoft.com/en-us/azure/architecture/example-scenario/data/sentinel-threat-intelligence#import-threat-indicators-with-the-platforms-data-connector)

### Requirements

- OpenCTI Platform >= 6.8

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `opencti` | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------------|------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `connector`       | config.yml                    | Docker environment variable             | Default                           | Mandatory | Description                                                                            |
|-----------------------------|-------------------------------|-----------------------------------------|-----------------------------------|-----------|----------------------------------------------------------------------------------------|
| ID                          | `id`                          | `CONNECTOR_ID`                          | /                                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                              |
| Live stream id              | `live_stream_id`              | `CONNECTOR_LIVE_STREAM_ID`              | /                                 | Yes       | The Live Stream ID of the stream created in the OpenCTI interface. A unique `UUIDv4`.  |
| Name                        | `name`                        | `CONNECTOR_NAME`                        | `Microsoft Sentinel Intel Master` | No        | Full name of the connector : `Microsoft Sentinel`.                                     |
| Scope                       | `scope`                       | `CONNECTOR_SCOPE`                       | `sentinel`                        | No        | Must be `sentinel`, not used in this connector.                                        |
| Log Level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | `error`                           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Live stream listen delete   | `live_stream_listen_delete`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | `true`                            | No        | The Live Stream listen delete must be `true`.                                          |
| Live stream no dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true`                            | No        | The Live Stream no dependencies must be `true`.                                        |

Below are the parameters you'll need to set for Sentinel Connector:

| Parameter `microsoft_sentinel_intel` | config.yml               | Docker environment variable                       | Default                    | Mandatory | Description                                                                         |
|--------------------------------------|--------------------------|---------------------------------------------------|----------------------------|-----------|-------------------------------------------------------------------------------------|
| Tenant ID                            | `tenant_id`              | `MICROSOFT_SENTINEL_INTEL_TENANT_ID`              | /                          | Yes       | Your Azure App Tenant ID, see the screenshot to help you find this information.     |
| Client ID                            | `client_id`              | `MICROSOFT_SENTINEL_INTEL_CLIENT_ID`              | /                          | Yes       | Your Azure App Client ID, see the screenshot to help you find this information.     |
| Client Secret                        | `client_secret`          | `MICROSOFT_SENTINEL_INTEL_CLIENT_SECRET`          | /                          | Yes       | Your Azure App Client secret, See the screenshot to help you find this information. |
| Workspace ID                         | `workspace_id`           | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_ID`           | /                          | Yes       | Your Azure Workspace ID                                                             |
| Workspace name                       | `workspace_name`         | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_NAME`         | /                          | Yes       | The name of the log analytics workspace                                             |
| Subscription ID                      | `subscription_id`        | `MICROSOFT_SENTINEL_INTEL_SUBSCRIPTION_ID`        | /                          | Yes       | The subscription id where the Log Analytics is                                      |
| Resource Group                       | `resource_group`         | `MICROSOFT_SENTINEL_INTEL_RESOURCE_GROUP`         | `default`                  | No        | The name of the resource group where the log analytics is                           |
| Source System                        | `source_system`          | `MICROSOFT_SENTINEL_INTEL_SOURCE_SYSTEM`          | `Opencti Stream Connector` | No        | The name of the source system displayed in Microsoft Sentinel                       |
| Delete Extensions                    | `delete_extensions`      | `MICROSOFT_SENTINEL_INTEL_DELETE_EXTENSIONS`      | `True`                     | No        | Delete the extensions in the stix bundle sent to the SIEM                           |
| Extra labels                         | `extra_labels`           | `MICROSOFT_SENTINEL_INTEL_EXTRA_LABELS`           | `[]`                       | No        | Extra labels added to the bundle sent. String separated by comma                    |
| Workspace API Version                | `workspace_api_version`  | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_API_VERSION`  | `2024-02-01-preview`       | No        | API version of the Microsoft log analytics workspace interface                      |
| Management API Version               | `management_api_version` | `MICROSOFT_SENTINEL_INTEL_MANAGEMENT_API_VERSION` | `2025-03-01`               | No        | API version of the Microsoft management interface                                   |

### Known Behavior

- When creating, updating or deleting and IOC, it can take few minutes before seeing it into Microsoft Sentinel TI
- Deleting indicators is supported using
  the [management API](https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence-indicator/delete?view=rest-securityinsights-2025-03-01&tabs=HTTP).
  source_system, workspace_name and subscription_id must be set to construct properly the URL