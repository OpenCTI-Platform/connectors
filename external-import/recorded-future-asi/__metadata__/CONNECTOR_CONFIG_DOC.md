# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| RECORDED_FUTURE_ASI_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| RECORDED_FUTURE_ASI_PROJECT_ID | `string` | ✅ | string |  | ASI project ID to fetch exposures from. |
| CONNECTOR_NAME | `string` |  | string | `"Recorded Future ASI Exposures"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["incident", "vulnerability", "ipv4-addr", "ipv6-addr", "domain-name"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| RECORDED_FUTURE_ASI_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.securitytrails.com/v2"` | API base URL. |
| RECORDED_FUTURE_ASI_API_V1_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.securitytrails.com/v1"` | v1 API base URL for exposure history activity. |
| RECORDED_FUTURE_ASI_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Default TLP level of the imported entities. |
| RECORDED_FUTURE_ASI_PORTAL_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional portal base URL for external reference deep links. |
| RECORDED_FUTURE_ASI_PAGE_LIMIT | `integer` |  | `1 <= x <= 1000` | `100` | Number of exposures to fetch per API page. |
| RECORDED_FUTURE_ASI_RUN_LIMIT | `integer` |  | `1 <= x ` | `null` | Max exposures to import per connector run. None = no limit (current behavior). |
| RECORDED_FUTURE_ASI_RETRY_MAX_ATTEMPTS | `integer` |  | `1 <= x <= 10` | `3` | Maximum HTTP request attempts (including the first) before giving up. |
| RECORDED_FUTURE_ASI_RETRY_INITIAL_SECONDS | `number` |  | `0.1 <= x <= 30` | `1` | Initial backoff delay in seconds for retried requests. |
| RECORDED_FUTURE_ASI_RETRY_MAX_SECONDS | `number` |  | `1 <= x <= 300` | `60` | Maximum backoff delay in seconds between retry attempts. |
| RECORDED_FUTURE_ASI_FILTER_SEVERITY_MIN | `string` |  | `unknown` `informational` `moderate` `critical` | `null` | Only import exposures at or above this severity. |
| RECORDED_FUTURE_ASI_FILTER_SEVERITY_EXACT | `string` |  | `unknown` `informational` `moderate` `critical` | `null` | Only import exposures matching this severity exactly. |
