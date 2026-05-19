# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MICROSOFT_SENTINEL_INCIDENTS_TENANT_ID | `string` | ✅ | string |  | Your Azure App Tenant ID, see the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INCIDENTS_CLIENT_ID | `string` | ✅ | string |  | Your Azure App Client ID, see the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INCIDENTS_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your Azure App Client secret, See the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INCIDENTS_SUBSCRIPTION_ID | `string` | ✅ | string |  | Your Microsoft Sentinel subscription ID. |
| MICROSOFT_SENTINEL_INCIDENTS_WORKSPACE_ID | `string` | ✅ | string |  | Your Microsoft Sentinel workspace ID. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Sentinel Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["sentinel"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| MICROSOFT_SENTINEL_INCIDENTS_IMPORT_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"2020-01-01T00:00:00Z"` | Import starting date (in YYYY-MM-DD format or YYYY-MM-DDTHH:MM:SSZ format) - used only if connector's state is not set. |
| MICROSOFT_SENTINEL_INCIDENTS_FILTER_LABELS | `array` |  | string | `[]` | Only incidents containing these specified labels will be retrieved and ingested (comma separated values). |
