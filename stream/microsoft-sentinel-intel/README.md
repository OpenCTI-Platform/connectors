# OpenCTI Microsoft Sentinel Intelligence Connector

This OpenCTI connector allows the ability to create, update and delete indicator data from your OpenCTI platform to Microsoft Sentinel
Microsoft has a detailed guide on how to get started with connecting your threat intelligence platform to Sentinel
found [here](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api).

## Installation

It is recommended to use a managed identity for authentication. It's also possible to use an app registration.
If you don't know how to get the `tenant_id`, `client_id`, and `client_secret` for the app registration information, here's a screenshot to
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

- OpenCTI Platform >= 6.4

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
| Name                        | `name`                        | `CONNECTOR_NAME`                        | /       | Yes       | `Microsoft Sentinel`                   | Full name of the connector : `Microsoft Sentinel`.                                     |
| Scope                       | `scope`                       | `CONNECTOR_SCOPE`                       | /       | Yes       | `sentinel`                             | Must be `sentinel`, not used in this connector.                                        |
| Log Level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | /       | Yes       | `error`                                | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Live stream id              | `live_stream_id`              | `CONNECTOR_LIVE_STREAM_ID`              | /       | Yes       | `9f204482-47a4-4fa4-b88b-ff4f390f31dd` | The Live Stream ID of the stream created in the OpenCTI interface. A unique `UUIDv4`.  |
| Live stream listen delete   | `live_stream_listen_delete`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | /       | Yes       | `true`                                 | The Live Stream listen delete must be `true`.                                          |
| Live stream no dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | /       | Yes       | `true`                                 | The Live Stream no dependencies must be `true`.                                        |

Below are the parameters you'll need to set for Sentinel Connector:

| Parameter `microsoft_sentinel_intel` | config.yml               | Docker environment variable                       | Default                    | Mandatory | Example              | Description                                                                                                              |
|--------------------------------------|--------------------------|---------------------------------------------------|----------------------------|-----------|----------------------|--------------------------------------------------------------------------------------------------------------------------|
| Source System                        | `source_system`          | `MICROSOFT_SENTINEL_INTEL_SOURCE_SYSTEM`          | 'Opencti Stream Connector' | Yes       | /                    | The name of the source system displayed in Microsoft Sentinel                                                            |
| Workspace ID                         | `workspace_id`           | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_ID`           | /                          | Yes       | /                    | Your Azure Workspace ID                                                                                                  |
| Resource Group                       | `resource_group`         | `MICROSOFT_SENTINEL_INTEL_RESOURCE_GROUP`         | /                          | Yes       | /                    | The name of the resource group where the log analytics is                                                                |
| Subscription ID                      | `subscription_id`        | `MICROSOFT_SENTINEL_INTEL_SUBSCRIPTION_ID`        | /                          | Yes       | /                    | The subscription id where the Log Analytics is                                                                           |
| Workspace name                       | `workspace_name`         | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_NAME`         | /                          | Yes       | /                    | The name of the log analytics workspace                                                                                  |
| Delete Extensions                    | `delete_extensions`      | `MICROSOFT_SENTINEL_INTEL_DELETE_EXTENSIONS`      | True                       | No        | /                    | Delete the extensions in the stix bundle sent to the SIEM                                                                |
| Extra labels                         | `extra_labels`           | `MICROSOFT_SENTINEL_INTEL_EXTRA_LABELS`           | /                          | No        | "prod,detect"        | Extra labels added to the bundle sent. String separated by comma                                                         |
| Workspace API Version                | `workspace_api_version`  | `MICROSOFT_SENTINEL_INTEL_WORKSPACE_API_VERSION`  | '2024-02-01-preview'       | No        | "2024-02-01-preview" | API version of the Microsoft log analytics workspace interface                                                           |
| Management API Version               | `management_api_version` | `MICROSOFT_SENTINEL_INTEL_MANAGEMENT_API_VERSION` | '2025-03-01'               | No        | "2025-03-01"         | API version of the Microsoft management interface                                                                        |

Azure authentication is managed through the native Azure Python SDK and supports multiple credential types, including Service Principal, Managed Identity, and Workload Identity.
For more details, refer to the official Azure Identity documentation:
- [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential?view=azure-python)
- [EnvironmentCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.environmentcredential?view=azure-python)

| Parameter `azure_authentication` | config.yml | Docker environment variable | Default                              | Mandatory | Example                                | Description                                                   |
|----------------------------------|------------|-----------------------------|--------------------------------------|-----------|----------------------------------------|---------------------------------------------------------------|
| Client ID                        | ``         | `AZURE_CLIENT_ID`           | /                                    | Yes if SP | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | The Client ID of the Azure AD application (Service Principal) |
| Tenant ID                        | ``         | `AZURE_TENANT_ID`           | /                                    | Yes if SP | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | The Azure AD tenant ID                                        |
| Client Secret                    | ``         | `AZURE_CLIENT_SECRET`       | /                                    | Yes if SP | `your-client-secret`                   | The client secret of the Service Principal                    |
| Authority Host                   | ``         | `AZURE_AUTHORITY_HOST`      | `https://login.microsoftonline.com/` | No        | `https://login.microsoftonline.com/`   | Azure AD authority host                                       |

To minimize disruption from environment variable renaming, the original variables have been preserved but could be deprecated. 

| Parameter `microsoft_sentinel_intel` | config.yml      | Docker environment variable              | Default                       | Mandatory | Example                       | Description                                                                         |
|--------------------------------------|-----------------|------------------------------------------|-------------------------------|-----------|-------------------------------|-------------------------------------------------------------------------------------|
| Tenant ID                            | `tenant_id`     | `MICROSOFT_SENTINEL_INTEL_TENANT_ID`     | /                             | No        | /                             | Your Azure App Tenant ID, see the screenshot to help you find this information.     |
| Client ID                            | `client_id`     | `MICROSOFT_SENTINEL_INTEL_CLIENT_ID`     | /                             | No        | /                             | Your Azure App Client ID, see the screenshot to help you find this information.     |
| Client Secret                        | `client_secret` | `MICROSOFT_SENTINEL_INTEL_CLIENT_SECRET` | /                             | No        | /                             | Your Azure App Client secret, See the screenshot to help you find this information. |
| Login Url                            | `login_url`     | `MICROSOFT_SENTINEL_INTEL_LOGIN_URL`     | `https://login.microsoft.com` | No        | `https://login.microsoft.com` | Login URL for Microsoft which is `https://login.microsoft.com`                      |


### Known Behavior

- When creating, updating or deleting and IOC, it can take few minutes before seeing it into Microsoft Sentinel TI
- Deleting indicators is supported using the [management API](https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence-indicator/delete?view=rest-securityinsights-2025-03-01&tabs=HTTP). source_system, workspace_name and subscription_id must be set to construct properly the URL