# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Doppel Threat Intelligence"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["doppel"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| DOPPEL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.doppel.com/"` | Doppel API base URL. A trailing /v1 or /v2 is accepted and normalized to the selected api_version. |
| DOPPEL_API_VERSION | `string` |  | `v1` `v2` | `"v1"` | Doppel API version. Choose exactly one authentication mode: V1 API keys or V2 OAuth client credentials. |
| DOPPEL_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | V1 API key sent as the x-api-key header. Required for V1 and must be unset for V2. |
| DOPPEL_USER_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional V1 user API key sent as the x-user-api-key header. Must be unset for V2. |
| DOPPEL_ORGANIZATION_CODE | `string` |  | string | `null` | Optional V1 organization workspace code sent as the x-organization-code header. Must be unset for V2. |
| DOPPEL_CLIENT_ID | `string` |  | string | `null` | OAuth client ID required for V2 and must be unset for V1. |
| DOPPEL_CLIENT_SECRET | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | OAuth client secret required for V2 and must be unset for V1. |
| DOPPEL_TOKEN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional V2 OAuth token endpoint. Defaults to /oauth/token on the API base URL and must be unset for V1. |
| DOPPEL_TOKEN_AUDIENCE | `string` |  | Length: `string >= 1` | `"doppel-external"` | OAuth audience used only for the V2 client-credentials exchange. |
| DOPPEL_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
| DOPPEL_ALERTS_ENDPOINT | `string` |  | string | `"/alerts"` | API resource path for alert ingestion. A leading v1/ or v2/ is accepted and normalized to api_version. |
| DOPPEL_HISTORICAL_POLLING_DAYS | `integer` |  | integer | `30` | Determines the time-window for initial data fetching |
| DOPPEL_MAX_RETRIES | `integer` |  | integer | `3` | Configures automated error recovery from transient failures |
| DOPPEL_RETRY_DELAY | `integer` |  | integer | `30` | Controls the frequency of requests during error recovery |
| DOPPEL_PAGE_SIZE | `integer` |  | integer | `100` | Optimizes request volume and memory usage per fetch |
| DOPPEL_ENABLE_GROUPING_CASE | `boolean` |  | boolean | `false` | Enables creation of grouping cases |
| DOPPEL_ENABLE_RFT_CASE | `boolean` |  | boolean | `false` | Enables creation of RFT cases for takedown alerts |
