# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| HUNT_IO_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Authentication key for accessing the Hunt.io API. Obtain this from your Hunt.io account settings |
| CONNECTOR_NAME | `string` |  | string |  | `"Hunt IO"` | Display name for this connector instance in the OpenCTI platform |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Hunt IO"]` | Entity types or categories this connector will handle. Used for filtering and organization within OpenCTI |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | Time interval between consecutive data imports from Hunt.io. Controls how frequently the connector runs |
| HUNT_IO_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.hunt.io/v1/feeds/c2"` | Hunt.io API endpoint URL for the C2 threat intelligence feeds |
| HUNT_IO_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` |  | `"amber"` | Traffic Light Protocol (TLP) marking level to apply to imported data, controlling information sharing restrictions |
| CONNECTOR_HUNT_UI_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"https://api.hunt.io/v1/feeds/c2"` | Use HUNT_IO_API_BASE_URL instead. |
| CONNECTOR_HUNT_UI_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use HUNT_IO_API_KEY instead. |
| CONNECTOR_HUNT_UI_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | ⛔️ | `"amber"` | Use HUNT_IO_TLP_LEVEL instead. |
| CONNECTOR_HUNT_IO_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"https://api.hunt.io/v1/feeds/c2"` | Use HUNT_IO_API_BASE_URL instead. |
| CONNECTOR_HUNT_IO_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use HUNT_IO_API_KEY instead. |
| CONNECTOR_HUNT_IO_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | ⛔️ | `"amber"` | Use HUNT_IO_TLP_LEVEL instead. |
