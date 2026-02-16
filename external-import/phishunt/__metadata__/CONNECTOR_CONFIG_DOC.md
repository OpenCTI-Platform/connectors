# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Phishunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["phishunt"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P3D"` | The period of time to await between two runs of the connector. |
| PHISHUNT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | The API key for Phishunt. If not set, the connector will use the public feed. |
| PHISHUNT_CREATE_INDICATORS | `boolean` |  | boolean | `true` | If true then indicators will be created from Pulse indicators and added to the report. |
| PHISHUNT_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer | `40` | The default `x_opencti_score` to use for indicators. If no per indicator type score is set, this is the fallback default score. |
| PHISHUNT_X_OPENCTI_SCORE_DOMAIN | `integer` |  | integer | `null` | The `x_opencti_score` to use for Domain indicators. If not set, the default value is `default_x_opencti_score`. |
| PHISHUNT_X_OPENCTI_SCORE_IP | `integer` |  | integer | `null` | The `x_opencti_score` to use for IP indicators. If not set, the default value is `default_x_opencti_score`. |
| PHISHUNT_X_OPENCTI_SCORE_URL | `integer` |  | integer | `null` | The `x_opencti_score` to use for URL indicators. If not set, the default value is `default_x_opencti_score`. |
