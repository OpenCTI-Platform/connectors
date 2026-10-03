# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SENTINEL_ANALYTICS_RULES_TENANT_ID | `string` | ✅ | Length: `string >= 1` |  | Microsoft Entra ID tenant of the application. |
| SENTINEL_ANALYTICS_RULES_CLIENT_ID | `string` | ✅ | Length: `string >= 1` |  | Application (client) id of the Entra ID app registration. |
| SENTINEL_ANALYTICS_RULES_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Client secret of the app registration. The application needs the `Microsoft Sentinel Reader` role on the workspace (or its resource group). |
| SENTINEL_ANALYTICS_RULES_SUBSCRIPTION_ID | `string` | ✅ | Length: `string >= 1` |  | Azure subscription holding the Log Analytics workspace. |
| SENTINEL_ANALYTICS_RULES_RESOURCE_GROUP | `string` | ✅ | Length: `string >= 1` |  | Resource group of the Log Analytics workspace. |
| SENTINEL_ANALYTICS_RULES_WORKSPACE_NAME | `string` | ✅ | Length: `string >= 1` |  | Name of the Log Analytics workspace Microsoft Sentinel runs on. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Sentinel Analytics Rules"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Attack-Pattern", "SecurityPlatform"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). Every run reads the full rule set. |
| SENTINEL_ANALYTICS_RULES_MANAGEMENT_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://management.azure.com/"` | Azure Resource Manager endpoint. Change it for sovereign clouds (e.g. `https://management.usgovcloudapi.net`). |
| SENTINEL_ANALYTICS_RULES_LOGIN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://login.microsoftonline.com/"` | Microsoft Entra ID authority. Change it for sovereign clouds (e.g. `https://login.microsoftonline.us`). |
| SENTINEL_ANALYTICS_RULES_API_VERSION | `string` |  | Length: `string >= 1` | `"2025-07-01-preview"` | Microsoft.SecurityInsights API version. The default one returns NRT rules and sub-techniques. |
| SENTINEL_ANALYTICS_RULES_IMPORT_DISABLED_RULES | `boolean` |  | boolean | `true` | Import disabled rules too, with the deployment status `deployed` (enabled rules get `active`). When false, disabled rules are left out and count as removed. |
| SENTINEL_ANALYTICS_RULES_REQUEST_TIMEOUT | `integer` |  | `1 <= x ` | `60` | Timeout of each HTTP request, in seconds. |
| SENTINEL_ANALYTICS_RULES_MAX_RETRIES | `integer` |  | `0 <= x ` | `5` | Retries of a request failing with a rate limit (429), a server error (5xx) or a network error, with exponential backoff. |
| SENTINEL_ANALYTICS_RULES_PLATFORM_NAME | `string` |  | Length: `string >= 1` | `"Microsoft Sentinel"` | Name of the Security Platform the rules are deployed on in OpenCTI. |
| SENTINEL_ANALYTICS_RULES_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of that Security Platform (`security_platform_type`). |
| SENTINEL_ANALYTICS_RULES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
