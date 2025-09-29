# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| FEEDLY_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Feedly API key for authentication. Generate your API key at https://feedly.com/i/team/api |
| CONNECTOR_NAME | `string` |  | string | `"Feedly"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["feedly"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| FEEDLY_INTERVAL | `integer` |  | `0 < x ` | `60` | Polling interval in minutes for fetching and refreshing Feedly data. Determines how often the system checks for updates from Feedly streams. |
| FEEDLY_STREAM_IDS | `array` |  | string | `null` | Comma separated list of Feedly stream IDs to monitor. Each stream ID represents a specific feed or collection to import from Feedly. |
| FEEDLY_DAYS_TO_BACK_FILL | `integer` |  | `0 < x ` | `7` | Number of days to back fill for new streams. When a new stream is added, the connector will fetch articles from this many days in the past. |
