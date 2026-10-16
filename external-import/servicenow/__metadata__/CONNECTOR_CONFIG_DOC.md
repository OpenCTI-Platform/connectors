# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SERVICENOW_INSTANCE_NAME | `string` | ✅ | string |  | Corresponds to server instance name (will be used for API requests). |
| SERVICENOW_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Secure identifier used to validate access to ServiceNow APIs. |
| CONNECTOR_NAME | `string` |  | string | `"ServiceNow"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["ServiceNow"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | `0 < x ` | `500` | Connector queue max size in Mbytes. Default to 500. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `null` | Connector run-and-terminate flag. |
| SERVICENOW_API_VERSION | `string` |  | `v1` `v2` | `"v2"` | ServiceNow API version used for REST requests. |
| SERVICENOW_API_LEAKY_BUCKET_RATE | `integer` |  | `0 < x ` | `10` | Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty. |
| SERVICENOW_API_LEAKY_BUCKET_CAPACITY | `integer` |  | `0 < x ` | `10` | Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'. |
| SERVICENOW_API_RETRY | `integer` |  | `0 < x ` | `5` | Maximum number of retry attempts in case of API failure. |
| SERVICENOW_API_BACKOFF | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT30S"` | Exponential backoff duration between API retries (ISO 8601 duration format). |
| SERVICENOW_IMPORT_START_DATE | `string` |  | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | Start date of first import, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago). |
| SERVICENOW_STATE_TO_EXCLUDE | `array` |  | string | `null` | List of security incident states to exclude from import. |
| SERVICENOW_SEVERITY_TO_EXCLUDE | `array` |  | string | `null` | List of security incident severities to exclude from import. |
| SERVICENOW_PRIORITY_TO_EXCLUDE | `array` |  | string | `null` | List of security incident priorities to exclude from import. |
| SERVICENOW_COMMENT_TO_EXCLUDE | `array` |  | `private` `public` `auto` | `null` | List of comment types to exclude: private, public, auto |
| SERVICENOW_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"red"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. |
| SERVICENOW_OBSERVABLES_DEFAULT_SCORE | `integer` |  | `0 < x ` | `50` | Allows you to define a default score for observables and indicators when the 'promote_observables_as_indicators' variable is set to True. |
| SERVICENOW_PROMOTE_OBSERVABLES_AS_INDICATORS | `boolean` |  | boolean | `true` | Boolean to promote observables into indicators. |
| SERVICENOW_SYSPARM_DISPLAY_VALUE | `boolean` |  | boolean | `true` | Boolean controlling the ``sysparm_display_value`` query parameter sent to ServiceNow on every Table API call. Defaults to ``true`` (backwards-compatible — ServiceNow returns human-readable display strings). Set to ``false`` on instances that return non-ISO 8601 datetimes when ``sysparm_display_value=true`` is in effect, which the connector cannot parse. |
