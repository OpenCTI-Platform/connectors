# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| PROMPTINTEL_API_KEY | `string` | ✅ | string |  | API key for authenticating with PromptIntel. |
| CONNECTOR_NAME | `string` |  | string | `"PromptIntel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["promptintel"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| PROMPTINTEL_API_URL | `string` |  | string | `"https://api.promptintel.novahunting.ai/api/v1"` | Base URL for the PromptIntel API. |
| PROMPTINTEL_TLP_LEVEL | `string` |  | string | `"clear"` | TLP marking level: clear, green, amber, amber+strict, red. |
| PROMPTINTEL_SEVERITY_FILTER | `string` |  | string | `""` | Filter prompts by severity: critical, high, medium, low. Empty for all. |
| PROMPTINTEL_CATEGORY_FILTER | `string` |  | string | `""` | Filter prompts by category: manipulation, abuse, patterns, outputs. Empty for all. |
| PROMPTINTEL_IMPORT_START_LIMIT | `integer` |  | integer | `5000` | Maximum number of prompts to fetch on the first run (historical backfill). |
| PROMPTINTEL_IMPORT_LIMIT | `integer` |  | integer | `1000` | Maximum number of prompts to fetch on subsequent runs. |
