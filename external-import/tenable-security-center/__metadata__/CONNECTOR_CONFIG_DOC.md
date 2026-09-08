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
| TSC_EXPORT_SINCE | `string` | ✅ | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Datetime (ISO-8601) used as the starting point of the very first data retrieval. It is overwritten by the connector state after the first successful run. |
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
