# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CHECKFIRST_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL for the API endpoint (e.g., https://api.example.com). |
| CHECKFIRST_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication (sent in Api-Key header). |
| CONNECTOR_NAME | `string` |  | string | `"Checkfirst Import Connector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["checkfirst"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P7D"` | The period of time to await between two runs of the connector. |
| CHECKFIRST_API_ENDPOINT | `string` |  | string | `"/v1/articles"` | API endpoint path (e.g., /v1/articles). |
| CHECKFIRST_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"2025-03-27T14:03:18.659871Z"` | Only ingest articles published on or after this date. Accepts ISO 8601 absolute dates (e.g., 2024-01-01T00:00:00Z) or durations relative to now (e.g., P365D, P1Y, P6M, P4W). Defaults to 1 year ago. |
| CHECKFIRST_FORCE_REPROCESS | `boolean` |  | boolean | `false` | If true, ignore any saved connector state and start from page 1. Useful for debugging or re-importing all data. |
| CHECKFIRST_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking level applied to created STIX entities. |
| CHECKFIRST_MAX_ROW_BYTES | `integer` |  | integer | `null` | Skip any API row larger than this approximate number of bytes. |
