# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| VULMATCH_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The Vulmatch API key used for authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"Vulmatch"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["vulmatch"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | The period of time to await between two runs of the connector. |
| VULMATCH_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.vulmatch.com/"` | The Vulmatch API base URL. |
| VULMATCH_SBOM_ONLY | `boolean` |  | boolean |  | `false` | Only ingest vulnerabilities related to products in your Vulmatch SBoM (`true`), or every vulnerability that matches the filters (`false`). |
| VULMATCH_CVSS_V2_SCORE_MIN | `integer` |  | integer |  | `-1` | The minimum CVSS v2 base score of the vulnerabilities to ingest, as an integer between 1 and 10. Set to -1 to disable this filter. |
| VULMATCH_CVSS_V3_SCORE_MIN | `integer` |  | integer |  | `-1` | The minimum CVSS v3 base score of the vulnerabilities to ingest, as an integer between 1 and 10. Set to -1 to disable this filter. |
| VULMATCH_CVSS_V4_SCORE_MIN | `integer` |  | integer |  | `-1` | The minimum CVSS v4 base score of the vulnerabilities to ingest, as an integer between 1 and 10. Set to -1 to disable this filter. |
| VULMATCH_EPSS_SCORE_MIN | `number` |  | number |  | `-1` | The minimum EPSS score of the vulnerabilities to ingest, between 0 and 1. Set to -1 to disable this filter. |
| VULMATCH_DAYS_TO_BACKFILL | `integer` |  | integer |  | `90` | The number of days of historical data to import on the first run (capped at 365). |
| VULMATCH_INTERVAL_DAYS | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
