# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| INTEL471_API_USERNAME | `string` | ✅ | string |  |  | Intel 471 API username (HTTP Basic authentication). |
| INTEL471_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Intel 471 API key (HTTP Basic authentication password). |
| CONNECTOR_NAME | `string` |  | string |  | `"Intel 471 Darknet"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["intel471-darknet"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT10M"` | The period of time to await between two runs of the connector. |
| INTEL471_API_URL | `string` |  | string |  | `"https://api.intel471.com/v1"` | Base URL of the Intel 471 REST API. |
| INTEL471_DARKNET_INITIAL_HISTORY_ALERTS | `integer` |  | integer |  | `0` | Unix epoch (seconds) of the earliest alert to import on the first run. Subsequent runs only fetch alerts newer than the previous successful run. |
| INTEL471_DARKNET_TLP | `string` |  | string |  | `"AMBER"` | TLP marking applied to every entity created by the connector. One of 'CLEAR', 'WHITE', 'GREEN', 'AMBER', 'AMBER_STRICT' (or 'AMBER+STRICT'), 'RED' (case-insensitive). |
| CONNECTOR_RUN_EVERY | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
