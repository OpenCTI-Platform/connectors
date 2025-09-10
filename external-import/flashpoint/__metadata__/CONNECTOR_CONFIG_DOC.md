# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

> ⚠️ Additional properties are not allowed.

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` | ✅ | string |  | The name of the connector. |
| FLASHPOINT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key to connect to Flashpoint. |
| OPENCTI_JSON_LOGGING | `boolean` |  | boolean | `true` | Whether to format logs as JSON or not. |
| OPENCTI_SSL_VERIFY | `boolean` |  | boolean | `false` | Whether to check SSL certificate or not. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["flashpoint"]` | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_EXPOSE_METRICS | `boolean` |  | boolean | `false` | Whether to expose metrics or not. |
| CONNECTOR_METRICS_PORT | `integer` |  | integer | `9095` | The port to expose metrics. |
| CONNECTOR_ONLY_CONTEXTUAL | `boolean` |  | boolean | `false` | Whether to expose metrics or not. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `false` | Connector run-and-terminate flag. |
| CONNECTOR_VALIDATE_BEFORE_IMPORT | `boolean` |  | boolean | `false` | Whether to validate data before import or not. |
| CONNECTOR_QUEUE_PROTOCOL | `string` |  | string | `"amqp"` | The queue protocol to use. |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | integer | `500` | Connector queue max size in Mbytes. Default to pycti value. |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `true` | Connector send-to-queue flag. Default to True. |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `false` | Connector send-to-directory flag. |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` | Connector send-to-directory path. |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | integer | `7` | Connector send-to-directory retention. |
| FLASHPOINT_IMPORT_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The date from which to start importing data. |
| FLASHPOINT_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Whether to import reports from Flashpoint or not. |
| FLASHPOINT_INDICATORS_IN_REPORTS | `boolean` |  | boolean | `false` | Whether to include indicators in the reports imported from MispFeed or not. |
| FLASHPOINT_GUESS_RELATIONSHIPS_FROM_REPORTS | `boolean` |  | boolean | `false` | Whether to guess relationships between entities or not. |
| FLASHPOINT_IMPORT_INDICATORS | `boolean` |  | boolean | `true` | WHether to import indicators of compromise (IoCs) or not. |
| FLASHPOINT_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import alert data from Flashpoint or not. |
| FLASHPOINT_ALERT_CREATE_RELATED_ENTITIES | `boolean` |  | boolean | `false` | Whether to create alert related Channel entity and Media-Content observable or not. |
| FLASHPOINT_IMPORT_COMMUNITIES | `boolean` |  | boolean | `false` | Whether to import community data or not. |
| FLASHPOINT_COMMUNITIES_QUERIES | `array` |  | string | `["cybersecurity", "cyberattack"]` | List of community queries to execute. |
| FLASHPOINT_IMPORT_CCM_ALERTS | `boolean` |  | boolean | `false` | Whether to import Compromised Credentials Monitoring alerts or not. |
| FLASHPOINT_FRESH_CCM_ALERTS_ONLY | `boolean` |  | boolean | `true` | Whether to import only fresh Compromised Credentials Monitoring alerts or all of them. |
