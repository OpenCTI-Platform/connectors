# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| VULNCHECK_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | API key for authenticating with the VulnCheck API. |
| CONNECTOR_NAME | `string` |  | string |  | `"VulnCheck Connector"` | Display name for this connector instance in the OpenCTI platform. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["vulnerability", "malware", "threat-actor", "infrastructure", "location", "ip-addr", "indicator", "external-reference", "software", "report"]` | Entity types this connector will handle. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | Time interval between consecutive data imports. |
| VULNCHECK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.vulncheck.com/v3"` | Base URL for the VulnCheck API. |
| VULNCHECK_DATA_SOURCES | `string` |  | string |  | `"vulncheck-kev,nist-nvd2"` | Comma-separated list of data sources to ingest. Available: botnets, epss, exploits, initial-access, ipintel, nist-nvd2, ransomware, snort, suricata, threat-actors, vulncheck-kev, vulncheck-nvd2. |
| CONNECTOR_VULNCHECK_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use VULNCHECK_API_KEY instead. |
| CONNECTOR_VULNCHECK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"https://api.vulncheck.com/v3"` | Use VULNCHECK_API_BASE_URL instead. |
| CONNECTOR_VULNCHECK_DATA_SOURCES | `string` |  | string | ⛔️ | `"vulncheck-kev,nist-nvd2"` | Use VULNCHECK_DATA_SOURCES instead. |
