# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| ZEROFOX_USERNAME | `string` | ✅ | string |  |  | The username used to authenticate against the ZeroFox API. |
| ZEROFOX_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The password used to authenticate against the ZeroFox API. |
| CONNECTOR_NAME | `string` |  | string |  | `"ZeroFox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["zerofox"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | The period of time to await between two runs of the connector. |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean |  | `false` | Whether to update data already ingested into the platform. |
| ZEROFOX_FIRST_RUN | `string` |  | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | `"P1D"` | Start date to look back on the connector's very first run (ISO 8601 format, absolute date or duration, e.g. '2023-10-01' or 'P1D'). |
| ZEROFOX_COLLECTORS | `array` |  | string |  | `["c2-domains", "exploits", "malware", "phishing", "scanned_after", "ransomware", "vulnerabilities", "botnet"]` | Comma-separated list of ZeroFox CTI feeds to collect. When unset, all available feeds are collected.Available values are:  'c2-domains', 'exploits', 'malware', 'phishing', 'scanned_after', 'ransomware', 'vulnerabilities', 'botnet'. |
| CONNECTOR_RUN_EVERY | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| CONNECTOR_FIRST_RUN | `string` |  | string | ⛔️ | `null` | Use ZEROFOX_FIRST_RUN instead. |
