# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |  |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |  |
| THEHIVE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the TheHive instance. | ```https://thehive.changeme.com``` |
| THEHIVE_API_KEY | `string` | ✅ | string |  | API key used to authenticate against TheHive. |  |
| THEHIVE_ORGANIZATION_NAME | `string` | ✅ | string |  | Name of the organization used as the author of imported data in OpenCTI. | ```MyCompany``` |
| CONNECTOR_NAME | `string` |  | string | `"TheHive"` | The name of the connector. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | Period of time to await between two runs of the connector (ISO-8601). Currently informational: scheduling still uses 'thehive.interval' (minutes); this becomes the scheduling source in a future version. |  |
| THEHIVE_CHECK_SSL | `boolean` |  | boolean | `true` | Whether to verify TheHive's TLS certificate. |  |
| THEHIVE_IMPORT_FROM_DATE | `string` |  | string | `null` | Earliest creation/update date to import from, as an ISO-8601 datetime (e.g. '2021-01-01T00:00:00'). Defaults to the connector's first start time. | ```2021-01-01T00:00:00``` |
| THEHIVE_IMPORT_ONLY_TLP | `array` |  | string | `["0", "1", "2", "3", "4"]` | Comma-separated TheHive TLP levels (0-4) to import. | ```0,1,2,3,4``` |
| THEHIVE_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import TheHive alerts in addition to cases. |  |
| THEHIVE_IMPORT_ATTACHMENTS | `boolean` |  | boolean | `false` | Whether to import case attachments as STIX artifacts. |  |
| THEHIVE_SEVERITY_MAPPING | `array` |  | string | `["1:01 - low", "2:02 - medium", "3:03 - high", "4:04 - critical"]` | Comma-separated mapping of TheHive severity (1-4) to an OpenCTI severity label, as 'level:label' pairs. | ```1:01 - low,2:02 - medium,3:03 - high,4:04 - critical``` |
| THEHIVE_CASE_STATUS_MAPPING | `array` |  | string |  | Comma-separated mapping of TheHive case extendedStatus to an OpenCTI workflow status id, as 'thehive_status:opencti_status_id' pairs. |  |
| THEHIVE_TASK_STATUS_MAPPING | `array` |  | string |  | Comma-separated mapping of TheHive task status to an OpenCTI workflow status id, as 'thehive_status:opencti_status_id' pairs. |  |
| THEHIVE_ALERT_STATUS_MAPPING | `array` |  | string |  | Comma-separated mapping of TheHive alert status to an OpenCTI workflow status id, as 'thehive_status:opencti_status_id' pairs. |  |
| THEHIVE_USER_MAPPING | `array` |  | string |  | Comma-separated mapping of TheHive assignee email to an OpenCTI user id, as 'email:opencti_user_id' pairs. |  |
| THEHIVE_CASE_TAG_WHITELIST | `array` |  | string |  | Comma-separated list of case tags; if set, only cases bearing one of these tags are imported. |  |
| THEHIVE_INTERVAL | `integer` |  | `1 <= x ` | `5` | Number of minutes to wait between two runs of the connector. |  |
