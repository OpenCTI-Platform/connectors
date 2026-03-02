# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MOKN_CONSOLE_URL | `string` | ✅ | string |  | MokN console base URL. |
| MOKN_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | MokN API key. |
| CONNECTOR_NAME | `string` |  | string | `"MokN"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["mokn"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| MOKN_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking level. |
| MOKN_FIRST_RUN_DAYS_BACK | `integer` |  | `1 <= x ` | `30` | Number of days to retrieve on first execution. |
