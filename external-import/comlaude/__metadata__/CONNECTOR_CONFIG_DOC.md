# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| COMLAUDE_USERNAME | `string` | ✅ | string |  | ComLaude API username. |
| COMLAUDE_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ComLaude API password. |
| COMLAUDE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ComLaude API key. |
| COMLAUDE_GROUP_ID | `string` | ✅ | string |  | ComLaude group ID to search domains against. |
| CONNECTOR_NAME | `string` |  | string | `"Comlaude"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["comlaude", "stix"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT2H"` | The period of time to await between two runs of the connector. |
| COMLAUDE_SCORE | `integer` |  | integer | `0` | Default score for created indicators (0-100). |
| COMLAUDE_START_TIME | `string` |  | string | `"1970-01-01T00:00:00Z"` | Start time for domain search in ISO 8601 format. |
| COMLAUDE_LABELS | `array` |  | string | `[]` | Comma-separated labels to apply to created objects. |
