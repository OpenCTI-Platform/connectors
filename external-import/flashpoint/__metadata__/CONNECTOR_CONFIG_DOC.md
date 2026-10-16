# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| FLASHPOINT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key to connect to Flashpoint. |
| CONNECTOR_NAME | `string` |  | string | `"Flashpoint"` | The name of the connector. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["flashpoint"]` | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| FLASHPOINT_IMPORT_START_DATE | `string` |  | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | The date from which to start importing data, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago). |
| FLASHPOINT_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Whether to import reports from Flashpoint or not. |
| FLASHPOINT_GUESS_RELATIONSHIPS_FROM_REPORTS | `boolean` |  | boolean | `false` | Whether to guess relationships between entities or not. |
| FLASHPOINT_IMPORT_INDICATORS | `boolean` |  | boolean | `true` | Whether to import indicators of compromise (IoCs) or not. |
| FLASHPOINT_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import alert data from Flashpoint or not. |
| FLASHPOINT_ALERT_CREATE_RELATED_ENTITIES | `boolean` |  | boolean | `false` | Whether to create alert related Channel entity and Media-Content observable or not. |
| FLASHPOINT_IMPORT_COMMUNITIES | `boolean` |  | boolean | `false` | Whether to import community data or not. |
| FLASHPOINT_COMMUNITIES_QUERIES | `array` |  | string | `["cybersecurity", "cyberattack"]` | List of community queries to execute. |
| FLASHPOINT_IMPORT_CCM_ALERTS | `boolean` |  | boolean | `false` | Whether to import Compromised Credentials Monitoring alerts or not. |
| FLASHPOINT_FRESH_CCM_ALERTS_ONLY | `boolean` |  | boolean | `true` | Whether to import only fresh Compromised Credentials Monitoring alerts or all of them. |
| FLASHPOINT_INDICATOR_TLP | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:GREEN"` | TLP marking applied to imported indicators. |
