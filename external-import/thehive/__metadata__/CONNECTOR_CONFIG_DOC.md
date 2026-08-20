# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| THEHIVE_URL | `string` | ✅ | string |  |  | The URL of the TheHive instance. |
| THEHIVE_API_KEY | `string` | ✅ | string |  |  | The API key to authenticate to TheHive. |
| THEHIVE_ORGANIZATION_NAME | `string` | ✅ | string |  |  | The name of the organization in TheHive, used to create the identity in OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"TheHive"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["thehive"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT5M"` | The period of time to await between two runs of the connector. |
| THEHIVE_CHECK_SSL | `boolean` |  | boolean |  | `true` | Whether to verify SSL certificates when connecting to TheHive. |
| THEHIVE_IMPORT_FROM_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | The date from which to start importing data (ISO format, e.g. 2021-01-01T00:00:00). Defaults to current time. |
| THEHIVE_IMPORT_ONLY_TLP | `array` |  | string |  | `["0", "1", "2", "3", "4"]` | Comma-separated list of TLP levels to import (0=WHITE, 1=GREEN, 2=AMBER, 3=RED, 4=AMBER+STRICT). |
| THEHIVE_IMPORT_ALERTS | `boolean` |  | boolean |  | `true` | Whether to import alerts from TheHive. |
| THEHIVE_IMPORT_ATTACHMENTS | `boolean` |  | boolean |  | `false` | Whether to import attachments from TheHive cases. |
| THEHIVE_SEVERITY_MAPPING | `array` |  | string |  | `["1:01 - low", "2:02 - medium", "3:03 - high", "4:04 - critical"]` | Comma-separated mapping of TheHive severity levels to OpenCTI severity labels (e.g. 1:low,2:medium,3:high,4:critical). |
| THEHIVE_CASE_STATUS_MAPPING | `array` |  | string |  | `[]` | Comma-separated mapping of TheHive case extended status to OpenCTI workflow status IDs (e.g. Resolved:status-id-1). |
| THEHIVE_CASE_TAG_WHITELIST | `array` |  | string |  | `[]` | Comma-separated list of tags to whitelist for case import. If set, only cases with these tags are imported. |
| THEHIVE_TASK_STATUS_MAPPING | `array` |  | string |  | `[]` | Comma-separated mapping of TheHive task status to OpenCTI workflow status IDs (e.g. Waiting:status-id-1,InProgress:status-id-2). |
| THEHIVE_ALERT_STATUS_MAPPING | `array` |  | string |  | `[]` | Comma-separated mapping of TheHive alert extended status to OpenCTI workflow status IDs. |
| THEHIVE_USER_MAPPING | `array` |  | string |  | `[]` | Comma-separated mapping of TheHive assignee emails to OpenCTI user IDs (e.g. user@example.com:user-id-1). |
| THEHIVE_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
