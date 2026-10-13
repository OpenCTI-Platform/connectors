# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"Ransomware Connector"` | The connector name displayed in OpenCTI. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["identity", "attack-pattern", "course-of-action", "intrusion-set", "malware", "tool", "report"]` | Comma-separated STIX entity scope for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT10M"` | Duration between two scheduled runs of the connector. |
| RANSOMWARELIVE_API_BASE_URL | `string` |  | `https://api.ransomware.live/v2` `https://api-pro.ransomware.live` |  | `"https://api.ransomware.live/v2"` | Ransomware.live API base URL. |
| RANSOMWARELIVE_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | API key sent in `X-API-KEY` header (required for Ransomware.live API PRO use only). |
| RANSOMWARELIVE_PULL_HISTORY | `boolean` |  | boolean |  | `false` | Whether to pull historic data. It is not recommended to set it to `true` as there will be a large influx of data. |
| RANSOMWARELIVE_HISTORY_START_YEAR | `integer` |  | `0 < x ` |  | `2023` | Year (or YYYYMM) to start historical backfill from. Values older than `2020` are clamped to `2020-01` at runtime. |
| RANSOMWARELIVE_CREATE_THREAT_ACTOR | `boolean` |  | boolean |  | `false` | Whether to create a Threat Actor object. |
| RANSOMWARELIVE_CREATE_INTRUSION_SET | `boolean` |  | boolean |  | `true` | Whether to create an Intrusion Set object. |
| RANSOMWARELIVE_CREATE_CAMPAIGN | `boolean` |  | boolean |  | `false` | Whether to create a Campaign object. |
| RANSOMWARELIVE_CREATE_REPORT | `boolean` |  | boolean |  | `true` | Whether to create a Report object. |
| RANSOMWARELIVE_CREATE_LEAK_SITE_DOMAINS | `boolean` |  | boolean |  | `false` | Whether to create DomainName observables for ransomware group leak sites and link them to the IntrusionSet. |
| RANSOMWARELIVE_CREATE_LEAK_POST_REFS | `boolean` |  | boolean |  | `false` | Whether to include the leak post URL as a report external reference. |
| RANSOMWARELIVE_MARKING_VALUE | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:CLEAR"` | TLP marking attached to every emitted STIX object. |
| CONNECTOR_RUN_EVERY | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| CONNECTOR_PULL_HISTORY | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_PULL_HISTORY instead. |
| CONNECTOR_HISTORY_START_YEAR | `integer` |  | `0 < x ` | ⛔️ | `null` | Use RANSOMWARELIVE_HISTORY_START_YEAR instead. |
| CONNECTOR_CREATE_THREAT_ACTOR | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_THREAT_ACTOR instead. |
| CONNECTOR_CREATE_INTRUSION_SET | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_INTRUSION_SET instead. |
| CONNECTOR_CREATE_CAMPAIGN | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_CAMPAIGN instead. |
| CONNECTOR_CREATE_REPORT | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_REPORT instead. |
| CONNECTOR_CREATE_LEAK_SITE_DOMAINS | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_LEAK_SITE_DOMAINS instead. |
| CONNECTOR_CREATE_LEAK_POST_REFS | `boolean` |  | boolean | ⛔️ | `null` | Use RANSOMWARELIVE_CREATE_LEAK_POST_REFS instead. |
| CONNECTOR_MARKING_VALUE | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | ⛔️ | `null` | Use RANSOMWARELIVE_MARKING_VALUE instead. |
