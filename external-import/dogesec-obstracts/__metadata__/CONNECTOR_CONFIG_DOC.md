# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| OBSTRACTS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The Obstracts API key used to authenticate. |
| CONNECTOR_NAME | `string` |  | string |  | `"Obstracts"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["obstracts"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| OBSTRACTS_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.obstracts.com/"` | The URL of the Obstracts API. |
| OBSTRACTS_FEED_IDS | `array` |  | string |  | `[]` | Comma-separated list of Obstracts feed IDs to import. When empty, every feed the team is subscribed to is imported. |
| OBSTRACTS_DAYS_TO_BACKFILL | `integer` |  | integer |  | `7` | Number of days of posts to import for a feed that has not been imported yet. Recommended maximum: 365. |
| OBSTRACTS_INTERVAL_HOURS | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
