# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| SERVICENOW_INSTANCE_NAME | `string` | ✅ | string |  | Corresponds to server instance name (will be used for API requests). |
| SERVICENOW_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Secure identifier used to validate access to ServiceNow APIs. |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_NAME | `string` |  | string | `"ServiceNow"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"ServiceNow"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT24H"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | `0 < x ` | `null` | Connector queue max size in Mbytes. Default to 500. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `null` | Connector run-and-terminate flag. |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `null` | Connector send-to-queue flag. |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `null` | Connector send-to-directory flag. |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` | Connector send-to-directory path. |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | `0 < x ` | `null` | Connector send-to-directory retention in days. |
| SERVICENOW_API_VERSION | `string` |  | `v1` `v2` | `"v2"` | ServiceNow API version used for REST requests. |
| SERVICENOW_API_LEAKY_BUCKET_RATE | `integer` |  | `0 < x ` | `10` | Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty. |
| SERVICENOW_API_LEAKY_BUCKET_CAPACITY | `integer` |  | `0 < x ` | `10` | Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'. |
| SERVICENOW_API_RETRY | `integer` |  | `0 < x ` | `5` | Maximum number of retry attempts in case of API failure. |
| SERVICENOW_API_BACKOFF | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT30S"` | Exponential backoff duration between API retries (ISO 8601 duration format). |
| SERVICENOW_IMPORT_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) and/or Format: [`date`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) and/or Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | Start date of first import (ISO date format). |
| SERVICENOW_STATE_TO_EXCLUDE | `array` |  | string | `null` | List of security incident states to exclude from import. |
| SERVICENOW_SEVERITY_TO_EXCLUDE | `array` |  | string | `null` | List of security incident severities to exclude from import. |
| SERVICENOW_PRIORITY_TO_EXCLUDE | `array` |  | string | `null` | List of security incident priorities to exclude from import. |
| SERVICENOW_COMMENT_TO_EXCLUDE | `array` |  | `private` `public` `auto` | `null` | List of comment types to exclude: private, public, auto |
| SERVICENOW_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"red"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. |
| SERVICENOW_OBSERVABLES_DEFAULT_SCORE | `integer` |  | `0 < x ` | `50` | Allows you to define a default score for observables and indicators when the 'promote_observables_as_indicators' variable is set to True. |
| SERVICENOW_PROMOTE_OBSERVABLES_AS_INDICATORS | `boolean` |  | boolean | `true` | Boolean to promote observables into indicators. |
