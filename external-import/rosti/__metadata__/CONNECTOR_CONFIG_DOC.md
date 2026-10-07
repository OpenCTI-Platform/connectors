# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ROSTI_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Rösti API key (get one at https://rosti.dev/api). |
| CONNECTOR_NAME | `string` |  | string | `"Rösti"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Report", "Indicator", "Stix-Cyber-Observable", "Attack-Pattern", "Intrusion-Set", "Malware", "Tool", "Campaign", "Course-Of-Action", "Vulnerability"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). |
| ROSTI_API_BASE_URL | `string` |  | string | `"https://api.rosti.dev/v2"` | Base URL of the Rösti API v2. |
| ROSTI_IMPORT_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Where to start on the first run. Either an absolute date (e.g. '2026-01-01T00:00:00Z') or a duration relative to now (e.g. 'P30D'). Later runs resume from the connector state. |
| ROSTI_IMPORT_IOCS | `boolean` |  | boolean | `true` | Import IOCs as indicators and observables. |
| ROSTI_IMPORT_YARA | `boolean` |  | boolean | `true` | Import YARA rules as indicators (pattern type `yara`). |
| ROSTI_IMPORT_MITRE | `boolean` |  | boolean | `true` | Link MITRE ATT&CK techniques, groups, software, campaigns and mitigations to reports. |
| ROSTI_IMPORT_CVE | `boolean` |  | boolean | `true` | Import CVEs referenced by reports as vulnerabilities. |
| ROSTI_IOC_TYPES | `array` |  | string | `[]` | Comma-separated list of Rösti IOC types to import. Empty means all supported types. |
| ROSTI_IDS_ONLY | `boolean` |  | boolean | `false` | Only import IOCs flagged as suitable for detection (`ids: true`). |
| ROSTI_MAX_RISK_LEVEL | `integer` |  | `0 <= x <= 5` | `5` | Skip IOCs whose false-positive risk level is above this value (0 = nothing found ... 5 = very high). 5 imports everything. |
| ROSTI_DEFAULT_SCORE | `integer` |  | `0 <= x <= 100` | `50` | Score given to IOCs that have no false-positive risk information. |
| ROSTI_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object this connector creates. |
