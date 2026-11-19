# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| STIXIFY_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The Stixify API key used for authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"Stixify"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["stixify"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector (ISO-8601 duration, e.g. 'PT1H'). |
| STIXIFY_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.stixify.com/"` | The URL of the Stixify API. |
| STIXIFY_DOSSIER_IDS | `array` |  | string |  | `[]` | Comma-separated list of Stixify Dossier IDs. The Reports (and the objects extracted from them) in these Dossiers are imported into OpenCTI. The Dossiers must be visible to the team of the API key. At least one Dossier ID is needed: the connector stops at startup when none is set. |
| STIXIFY_INTERVAL_HOURS | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
