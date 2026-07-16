# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| MALCORE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Malcore API Key |
| CONNECTOR_NAME | `string` |  | string |  | `"Malcore"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| MALCORE_API_URL | `string` |  | string |  | `"https://api.malcore.io/api/feed"` | Malcore API URL |
| MALCORE_INTERVAL | `integer` |  | integer |  | `12` | Interval between two executions, in hours (must be > 1) |
| MALCORE_SCORE | `integer` |  | integer | ⛔️ | `100` | Parameter not used at this moment, but could be used as a default indicator/observable score at a later date |
| MALCORE_LIMIT | `integer` |  | integer | ⛔️ | `10000` | Parameter not used at this moment, but could be used as a limit on the number of entities to be retrieved per request at a later date |
