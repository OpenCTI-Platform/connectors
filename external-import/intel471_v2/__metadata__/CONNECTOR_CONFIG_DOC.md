# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| INTEL471_API_USERNAME | `string` | ✅ | string |  | Titan/Verity471 API username |
| INTEL471_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Titan/Verity471 API key |
| INTEL471_BACKEND | `string` |  | `titan` `verity471` | `titan` | Specifies the ingestion source platform. Supports Titan and Verity471, with the latter providing full parity plus extended data type support. |
| CONNECTOR_NAME | `string` |  | string | `"Intel471 v2"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["malware", "vulnerability", "indicator"]` | The scope of the connector, e.g. 'malware, vulnerability, indicator'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| INTEL471_INTERVAL_INDICATORS | `integer` |  | integer | `60` | How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_INDICATORS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the malware indicators should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_YARA | `integer` |  | integer | `60` | How often YARA rules should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_YARA | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the YARA rules should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_CVES | `integer` |  | integer | `120` | How often CVE reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_CVES | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the CVE reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_INTERVAL_REPORTS | `integer` |  | integer | `120` | How often reports should be fetched in minutes. If not set, the stream will not be enabled. |
| INTEL471_INITIAL_HISTORY_REPORTS | `integer` |  | integer | `0` | Initial date in epoch milliseconds UTC, such as `1643989649000`, the reports should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates. |
| INTEL471_PROXY | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional Proxy URL, for example `http://user:pass@localhost:3128` |
| INTEL471_IOC_SCORE | `integer` |  | integer | `70` | Indicator score. Defaults to `70`. |
