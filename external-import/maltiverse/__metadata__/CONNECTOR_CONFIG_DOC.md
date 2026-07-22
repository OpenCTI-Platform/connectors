# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| MALTIVERSE_USER | `string` | ✅ | string |  |  | Maltiverse account username/email. |
| MALTIVERSE_PASSWD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Maltiverse account password. |
| MALTIVERSE_FEEDS | `string` | ✅ | string |  |  | Comma-separated list of feed/collection IDs to fetch. |
| CONNECTOR_NAME | `string` |  | string |  | `"Maltiverse"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| MALTIVERSE_POLL_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
