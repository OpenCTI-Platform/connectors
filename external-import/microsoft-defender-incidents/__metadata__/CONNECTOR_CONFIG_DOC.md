# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MICROSOFT_DEFENDER_INCIDENTS_TENANT_ID | `string` | ✅ | string |  | Azure Tenant ID for Microsoft Graph API authentication. |
| MICROSOFT_DEFENDER_INCIDENTS_CLIENT_ID | `string` | ✅ | string |  | Azure App Client ID for Microsoft Graph API authentication. |
| MICROSOFT_DEFENDER_INCIDENTS_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Azure App Client Secret for Microsoft Graph API authentication. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Defender Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["defender"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| MICROSOFT_DEFENDER_INCIDENTS_IMPORT_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"2025-01-01T00:00:00Z"` | Start date for importing incidents in ISO 8601 format (e.g. '2025-01-01T00:00:00Z'). Used only on the first run; subsequent runs use the stored state. |
| MICROSOFT_DEFENDER_INCIDENTS_API_BASE_URL | `string` |  | string | `"https://graph.microsoft.com/v1.0"` | Microsoft Graph API base URL. |
| MICROSOFT_DEFENDER_INCIDENTS_INCIDENT_PATH | `string` |  | string | `"/security/incidents"` | Microsoft Graph API path for retrieving security incidents. |
