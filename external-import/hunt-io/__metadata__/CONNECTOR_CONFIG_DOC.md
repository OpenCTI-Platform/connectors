# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_DURATION_PERIOD | `string` | ✅ | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The period of time to await between two runs of the connector. |
| HUNT_IO_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key |
| CONNECTOR_NAME | `string` |  | string | `"Hunt IO"` | Connector name |
| CONNECTOR_SCOPE | `array` |  | string | `["Hunt IO"]` | Connector scope |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| HUNT_IO_API_BASE_URL | `string` |  | string |  | API base URL |
| HUNT_IO_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | `"amber"` | TLP level |
