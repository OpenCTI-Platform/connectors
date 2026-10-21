# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| INTEL471_API_USERNAME | `string` | ✅ | string |  | Verity Client ID or Titan API Username. |
| INTEL471_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Verity Client Secret or Titan API Key. |
| CONNECTOR_NAME | `string` |  | string | `"Intel471 v2"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["malware", "vulnerability", "indicator"]` | The scope of the connector, e.g. 'malware, vulnerability, indicator'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| INTEL471_BACKEND | `string` |  | `titan` `verity471` | `"titan"` | Backend to use for Intel471 API calls. Defaults to `titan`. |
| INTEL471_INTERVAL_INDICATORS | `integer` |  | integer | `60` | How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_INDICATORS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the malware indicators should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds. |
| INTEL471_INTERVAL_CVES | `integer` |  | integer | `120` | How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_CVES | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the CVE reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds. |
| INTEL471_INTERVAL_REPORTS | `integer` |  | integer | `120` | How often reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_REPORTS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds. |
| INTEL471_INTERVAL_YARA | `integer` |  | integer | `60` | How often YARA rules should be fetched in minutes (Titan only). If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_YARA | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the YARA rules should be fetched from on the connector's first run (Titan only). If not set, they will be fetched from the connector's start date. Excludes historical dates. A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds. |
| INTEL471_INTERVAL_ALERTS | `integer` |  | integer | `0` | How often watcher alerts should be fetched in minutes (Verity471 only). Defaults to `0`, which leaves the stream disabled; set a non-zero interval to enable it. |
| INTEL471_INITIAL_HISTORY_ALERTS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the watcher alerts should be fetched from on the connector's first run (Verity471 only). If not set, they will be fetched from the connector's start date. Excludes historical dates. A value given in epoch seconds, such as `1643989649`, is detected and converted to milliseconds. |
| INTEL471_WATCHER_GROUP_IDS | `array` |  | string | `[]` | Optional comma-separated list of watcher group IDs to restrict the alerts stream to (Verity471 only). If not set, alerts from all watcher groups are fetched. |
| INTEL471_WATCHER_IDS | `array` |  | string | `[]` | Optional comma-separated list of watcher IDs to restrict the alerts stream to (Verity471 only). If not set, alerts from all watchers are fetched. |
| INTEL471_STATUSES | `array` |  | string | `[]` | Optional comma-separated list of alert statuses to restrict the alerts stream to (Verity471 only). Allowed values: `generated`, `needs_action`, `in_progress`, `completed`, `false_positive`. If not set, alerts of all statuses are fetched. |
| INTEL471_IS_TRASHED_INCLUDED | `boolean` |  | boolean | `false` | Whether to include trashed alerts in the alerts stream (Verity471 only). Defaults to `false`. |
| INTEL471_PROXY | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional Proxy URL, for example `http://user:pass@localhost:3128` |
| INTEL471_IOC_SCORE | `integer` |  | integer | `70` | Indicator score. Defaults to `70`. |
