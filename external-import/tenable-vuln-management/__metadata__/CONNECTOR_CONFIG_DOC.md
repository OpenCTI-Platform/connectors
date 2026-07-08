# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| TENABLE_VULN_MANAGEMENT_API_ACCESS_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Tenable API access key. |
| TENABLE_VULN_MANAGEMENT_API_SECRET_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Tenable API secret key. |
| CONNECTOR_NAME | `string` |  | string |  | `"TenableVulnManagement"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| TENABLE_VULN_MANAGEMENT_API_BASE_URL | `string` |  | string |  | `"https://cloud.tenable.com"` | Base URL for the Tenable API. |
| TENABLE_VULN_MANAGEMENT_API_TIMEOUT | `integer` |  | integer |  | `30` | Timeout for API requests in seconds. |
| TENABLE_VULN_MANAGEMENT_API_BACKOFF | `integer` |  | integer |  | `1` | Time (in seconds) to wait before retrying after receiving a 429 response from the API. |
| TENABLE_VULN_MANAGEMENT_API_RETRIES | `integer` |  | integer |  | `5` | Number of retries in case of failure. |
| TENABLE_VULN_MANAGEMENT_EXPORT_SINCE | `string` |  | string |  | `"1970-01-01T00:00:00+00"` | Date from which to start pulling vulnerability data. |
| TENABLE_VULN_MANAGEMENT_MIN_SEVERITY | `string` |  | string |  | `"low"` | The minimum severity level of vulnerabilities to import (`low`, `medium`, `high`, `critical`). |
| TENABLE_VULN_MANAGEMENT_MARKING_DEFINITION | `string` |  | string |  | `"TLP:CLEAR"` | Default marking definition for imported data (e.g., `TLP:AMBER`, `TLP:GREEN`, `TLP:CLEAR`). |
| TENABLE_VULN_MANAGEMENT_NUM_THREADS | `integer` |  | integer |  | `1` | Number of threads to use for the connector. |
| TIO_API_BASE_URL | `string` |  | string | ⛔️ | `"https://cloud.tenable.com"` | Use TENABLE_VULN_MANAGEMENT_API_BASE_URL instead. |
| TIO_API_ACCESS_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use TENABLE_VULN_MANAGEMENT_API_ACCESS_KEY instead. |
| TIO_API_SECRET_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use TENABLE_VULN_MANAGEMENT_API_SECRET_KEY instead. |
| TIO_API_TIMEOUT | `integer` |  | integer | ⛔️ | `30` | Use TENABLE_VULN_MANAGEMENT_API_TIMEOUT instead. |
| TIO_API_BACKOFF | `integer` |  | integer | ⛔️ | `1` | Use TENABLE_VULN_MANAGEMENT_API_BACKOFF instead. |
| TIO_API_RETRIES | `integer` |  | integer | ⛔️ | `5` | Use TENABLE_VULN_MANAGEMENT_API_RETRIES instead. |
| TIO_EXPORT_SINCE | `string` |  | string | ⛔️ | `"1970-01-01T00:00:00+00"` | Use TENABLE_VULN_MANAGEMENT_EXPORT_SINCE instead. |
| TIO_MIN_SEVERITY | `string` |  | string | ⛔️ | `"low"` | Use TENABLE_VULN_MANAGEMENT_MIN_SEVERITY instead. |
| TIO_MARKING_DEFINITION | `string` |  | string | ⛔️ | `"TLP:CLEAR"` | Use TENABLE_VULN_MANAGEMENT_MARKING_DEFINITION instead. |
| TIO_NUM_THREADS | `integer` |  | integer | ⛔️ | `1` | Use TENABLE_VULN_MANAGEMENT_NUM_THREADS instead. |
