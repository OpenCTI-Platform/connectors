# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |
| INTEL471_API_USERNAME | `string` | ✅ | string |  | Titan API username |
| INTEL471_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Titan API key |
| CONNECTOR_NAME | `string` |  | string | `"Intel471 v2"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `null` |  | null | `null` | Dot not use. Not implemented in the connector yet. |
| INTEL471_INTERVAL_INDICATORS | `integer` |  | integer | `0` | How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_INDICATORS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the malware indicators should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_YARA | `integer` |  | integer | `0` | How often YARA rules should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_YARA | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the YARA rules should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_CVES | `integer` |  | integer | `0` | How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_CVES | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the CVE reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_REPORTS | `integer` |  | integer | `0` | How often reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_REPORTS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_PROXY | `string` |  | string | `null` | Optional Proxy URL, for example `http://user:pass@localhost:3128` |
| INTEL471_IOC_SCORE | `integer` |  | integer | `70` | Indicator score. Defaults to `70`. |
