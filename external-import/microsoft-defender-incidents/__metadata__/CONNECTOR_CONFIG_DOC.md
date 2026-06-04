# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MICROSOFT_DEFENDER_INCIDENTS_TENANT_ID | `string` | ✅ | string |  | Your Azure App Tenant ID, see connector's README to help you find this information. |
| MICROSOFT_DEFENDER_INCIDENTS_CLIENT_ID | `string` | ✅ | string |  | Your Azure App Client ID, see connector's README to help you find this information. |
| MICROSOFT_DEFENDER_INCIDENTS_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your Azure App Client secret, see connector's README to help you find this information. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Defender Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["defender"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| MICROSOFT_DEFENDER_INCIDENTS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://graph.microsoft.com/v1.0"` | The Microsoft Graph API base URL used to retrieve incidents. |
| MICROSOFT_DEFENDER_INCIDENTS_INCIDENT_PATH | `string` |  | string | `"/security/incidents"` | The Microsoft Graph API path used to retrieve incidents. |
| MICROSOFT_DEFENDER_INCIDENTS_IMPORT_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"2020-01-01T00:00:00Z"` | The date from which to start importing incidents, in ISO 8601 format (e.g. `2025-01-01T00:00:00Z`). Only used when the connector's state is not set yet. |
