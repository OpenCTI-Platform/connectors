# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |
| DOPPEL_API_KEY | `string` | ✅ | string |  | API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"Doppel Threat Intelligence"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| DOPPEL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.doppel.com/v1"` | API base URL. |
| DOPPEL_USER_API_KEY | `string` |  | string | `null` | Used for user-specific identity |
| DOPPEL_ORGANIZATION_CODE | `string` |  | string | `null` | Identifies the specific organizational workspace for multi-tenant keys |
| DOPPEL_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
| DOPPEL_ALERTS_ENDPOINT | `string` |  | string | `"/alerts"` | Specifies the API resource path for alert ingestion |
| DOPPEL_HISTORICAL_POLLING_DAYS | `integer` |  | integer | `30` | Determines the time-window for initial data fetching |
| DOPPEL_MAX_RETRIES | `integer` |  | integer | `3` | Configures automated error recovery from transient failures |
| DOPPEL_RETRY_DELAY | `integer` |  | integer | `30` | Controls the frequency of requests during error recovery |
| DOPPEL_PAGE_SIZE | `integer` |  | integer | `100` | Optimizes request volume and memory usage per fetch |
