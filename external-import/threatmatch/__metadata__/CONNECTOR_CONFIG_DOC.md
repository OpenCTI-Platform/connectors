# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| THREATMATCH_CLIENT_ID | `string` | ✅ | string |  |  | ThreatMatch OAuth2 client id (Client Credentials). |
| THREATMATCH_CLIENT_SECRET | `string` | ✅ | string |  |  | ThreatMatch OAuth2 client secret. |
| CONNECTOR_NAME | `string` |  | string |  | `"ThreatMatch"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["threatmatch"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | Polling frequency as an ISO-8601 duration (e.g., 'P1D'). |
| THREATMATCH_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://eu.threatmatch.com/"` | Base URL of the ThreatMatch API. |
| THREATMATCH_IMPORT_FROM_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Relative ISO-8601 duration (e.g., 'P30D') used to set the first import window. Applied on the first run only. Defaults to 30 days ago from the current date. |
| THREATMATCH_IMPORT_PROFILES | `boolean` |  | boolean |  | `true` | Import the ThreatMatch profiles dataset. |
| THREATMATCH_IMPORT_ALERTS | `boolean` |  | boolean |  | `true` | Import the ThreatMatch alerts dataset. |
| THREATMATCH_IMPORT_IOCS | `boolean` |  | boolean |  | `true` | Import the ThreatMatch IOCs dataset. |
| THREATMATCH_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` |  | `"amber"` | Default TLP marking applied when missing on source objects. |
| THREATMATCH_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean |  | `true` | Map ThreatMatch threat-actor objects to STIX intrusion-set. |
| THREATMATCH_INTERVAL | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. (removal scheduled for 2027-01-01) |
