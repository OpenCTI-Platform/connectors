# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"IPsum"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["ipsum"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_IPSUM_API_BASE_URL | `string` |  | string | `"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt"` | The URL of the IPsum feed to fetch (levels 1-8 are available). |
| CONNECTOR_IPSUM_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional GitHub API key used to avoid rate limiting. |
| CONNECTOR_IPSUM_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer | `60` | Default x_opencti_score to set on imported observables. |
| CONNECTOR_IPSUM_TLP_LEVEL | `string` |  | string | `"white"` | TLP marking to apply to imported data (white, clear, green, amber, amber+strict, red). |
