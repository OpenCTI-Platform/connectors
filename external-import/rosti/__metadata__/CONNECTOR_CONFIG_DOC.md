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
| ROSTI_IMPORT_SINCE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | Where to start on the first run. Either an absolute date (e.g. '2026-01-01T00:00:00Z') or a duration relative to now (e.g. 'P30D'). Later runs resume from the connector state. |
| ROSTI_IMPORT_IOCS | `boolean` |  | boolean | `true` | Import IOCs as indicators and observables. |
| ROSTI_IMPORT_YARA | `boolean` |  | boolean | `true` | Import YARA rules as indicators (pattern type `yara`). |
| ROSTI_IMPORT_MITRE | `boolean` |  | boolean | `true` | Link MITRE ATT&CK techniques, groups, software, campaigns and mitigations to reports. |
| ROSTI_IMPORT_CVE | `boolean` |  | boolean | `true` | Import CVEs referenced by reports as vulnerabilities. |
| ROSTI_IOC_TYPES | `array` |  | string | `[]` | Comma-separated list of Rösti IOC types to import. Empty means all supported types. |
| ROSTI_IDS_ONLY | `boolean` |  | boolean | `false` | Only import IOCs flagged as suitable for detection (`ids: true`). |
| ROSTI_MAX_RISK_LEVEL | `integer` |  | `0 <= x <= 5` | `5` | Skip IOCs whose false-positive risk level is above this value (0 = nothing found ... 5 = very high). 5 imports everything. |
| ROSTI_DEFAULT_SCORE | `integer` |  | `0 <= x <= 100` | `50` | Score given to IOCs that have no false-positive risk information. |
| ROSTI_REPLACE_REPORT_OBJECTS | `boolean` |  | boolean | `false` | When a Rösti report is updated, replace the objects the report contains in OpenCTI instead of adding to them. IOCs removed from the report in Rösti then leave the OpenCTI report too, but so does anything an analyst added to the report in OpenCTI. |
| ROSTI_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object this connector creates. |
