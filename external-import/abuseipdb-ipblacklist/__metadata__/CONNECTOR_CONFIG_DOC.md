# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ABUSEIPDB_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your AbuseIPDB API key. |
| CONNECTOR_NAME | `string` |  | string | `"AbuseipdbIpblacklist"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["abuseipdb-blacklist"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| ABUSEIPDB_API_URL | `string` |  | string | `"https://api.abuseipdb.com/api/v2/blacklist"` | AbuseIPDB API endpoint URL. |
| ABUSEIPDB_SCORE | `integer` |  | integer | `75` | Minimum confidence score threshold for IP addresses. |
| ABUSEIPDB_LIMIT | `integer` |  | integer | `500000` | Maximum number of IPs to fetch. |
| ABUSEIPDB_CREATE_INDICATOR | `boolean` |  | boolean | `false` | Whether to create Indicators from observables. |
| ABUSEIPDB_TLP_LEVEL | `string` |  | string | `"clear"` | TLP marking for imported data (`clear`, `green`, `amber`, `amber+strict`, `red`). |
| ABUSEIPDB_IPVERSION | `string` |  | `4` `6` `mixed` | `"mixed"` | IP version filter: `4`, `6`, or `mixed`. |
| ABUSEIPDB_EXCEPTCOUNTRY | `string` |  | string | `null` | Comma-separated country codes to exclude (e.g., `RU,CN`). |
| ABUSEIPDB_ONLYCOUNTRY | `string` |  | string | `null` | Comma-separated country codes to include only. |
