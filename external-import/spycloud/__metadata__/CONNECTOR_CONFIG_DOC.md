# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SPYCLOUD_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | SpyCloud API base URL (a trailing slash is added if missing). |
| SPYCLOUD_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | SpyCloud API key. |
| CONNECTOR_NAME | `string` |  | string | `"SpyCloud"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["spycloud"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| SPYCLOUD_SEVERITY_LEVELS | `array` |  | `2` `5` `20` `25` | `[]` | Comma-separated list of severities to filter breach records (allowed values are 2, 5, 20, 25). Leave empty to import all severities. |
| SPYCLOUD_WATCHLIST_TYPES | `array` |  | `email` `domain` `subdomain` `ip` | `[]` | Comma-separated list of watchlist types to filter breach records (allowed values are 'email', 'domain', 'subdomain', 'ip'). Leave empty to import all watchlist types. |
| SPYCLOUD_TLP_LEVEL | `string` |  | `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | TLP level to set on imported entities. |
| SPYCLOUD_IMPORT_START_DATE | `string` |  | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | The date to start importing breach records from, used only if the connector's state is not set. Can be either absolute (ISO 8601 date, e.g. '2024-01-01T00:00:00Z') or relative (ISO 8601 duration, e.g. 'P30D' for 30 days ago). |
