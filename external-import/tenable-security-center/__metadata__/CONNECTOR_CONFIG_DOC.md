# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| TSC_API_BASE_URL | `string` | ✅ | string |  | Base URL of the Tenable Security Center API instance. |
| TSC_API_ACCESS_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Access key used to authenticate against the Tenable Security Center API. |
| TSC_API_SECRET_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Secret key used to authenticate against the Tenable Security Center API. |
| TSC_EXPORT_SINCE | `string` | ✅ | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | Starting point of the very first data retrieval, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago). It is overwritten by the connector state after the first successful run. |
| CONNECTOR_NAME | `string` |  | string | `"Tenable Security Center"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["vulnerability"]` | The scope of the connector, i.e. the type of STIX objects it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT12H"` | The period of time to await between two runs of the connector. |
| TSC_API_TIMEOUT | `integer` |  | `1 <= x ` | `30` | Timeout, in seconds, of the Tenable Security Center API requests. |
| TSC_API_BACKOFF | `integer` |  | `0 <= x ` | `5` | Backoff duration, in seconds, between two Tenable Security Center API retries. |
| TSC_API_RETRIES | `integer` |  | `0 <= x ` | `3` | Number of retries of the Tenable Security Center API requests. |
| TSC_SEVERITY_MIN_LEVEL | `string` |  | `info` `low` `medium` `high` `critical` | `"high"` | Minimum severity level of the findings to import. |
| TSC_PROCESS_SYSTEMS_WITHOUT_VULNERABILITIES | `boolean` |  | boolean | `false` | Whether to import the systems that have no vulnerability attached. |
| TSC_MARKING_DEFINITION | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:RED` | `"TLP:CLEAR"` | TLP marking definition applied to all the imported entities. |
| TSC_NUMBER_THREADS | `integer` |  | `1 <= x ` | `1` | Number of threads used to retrieve data from Tenable Security Center. |
