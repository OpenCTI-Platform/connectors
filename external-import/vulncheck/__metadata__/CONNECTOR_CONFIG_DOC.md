# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| VULNCHECK_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API key used to authenticate against the VulnCheck API. |
| CONNECTOR_NAME | `string` |  | string |  | `"VulnCheck"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["vulnerability", "malware", "threat-actor", "infrastructure", "location", "ip-addr", "indicator", "external-reference", "attack-pattern", "course-of-action", "x-mitre-data-source", "report"]` | Comma-separated STIX object types to import, e.g. `vulnerability,malware,threat-actor,infrastructure,location,ip-addr,indicator,external-reference,attack-pattern,course-of-action,x-mitre-data-source,report` (add `software` only if prepared for the volume — see [Data Volume](#data-volume)). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| VULNCHECK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.vulncheck.com/v3"` | The base URL of the VulnCheck API. |
| VULNCHECK_DATA_SOURCES | `array` |  | string |  | `["vulncheck-kev", "nist-nvd2"]` | Comma-separated list of VulnCheck data sources to ingest. |
| VULNCHECK_NVD2_PULL_HISTORY | `boolean` |  | boolean |  | `false` | First run only: when true, pull the full NVD2 history (no date filter). When false, the first run is bounded by nvd2_max_date_range. |
| VULNCHECK_NVD2_MAX_DATE_RANGE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P120D"` | First run only: how far back (last-modified) to pull when not pulling full history. ISO-8601 duration, e.g. P120D. |
| VULNCHECK_NVD2_LAST_MOD_START_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Optional ISO-8601 date override for a manual NVD2 backfill (start). |
| VULNCHECK_NVD2_LAST_MOD_END_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Optional ISO-8601 date override for a manual NVD2 backfill (end). |
| CONNECTOR_VULNCHECK_API_KEY | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_API_KEY instead. |
| CONNECTOR_VULNCHECK_API_BASE_URL | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_API_BASE_URL instead. |
| CONNECTOR_VULNCHECK_DATA_SOURCES | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_DATA_SOURCES instead. |
| CONNECTOR_VULNCHECK_NVD2_PULL_HISTORY | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_NVD2_PULL_HISTORY instead. |
| CONNECTOR_VULNCHECK_NVD2_MAX_DATE_RANGE | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_NVD2_MAX_DATE_RANGE instead. |
| CONNECTOR_VULNCHECK_NVD2_LAST_MOD_START_DATE | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_NVD2_LAST_MOD_START_DATE instead. |
| CONNECTOR_VULNCHECK_NVD2_LAST_MOD_END_DATE | `string` |  | string | ⛔️ | `null` | Use VULNCHECK_NVD2_LAST_MOD_END_DATE instead. |
