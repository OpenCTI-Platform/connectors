# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| THREATMATCH_CLIENT_ID | `string` | ✅ | string |  |  | ThreatMatch OAuth2 client id (Client Credentials). |
| THREATMATCH_CLIENT_SECRET | `string` | ✅ | string |  |  | ThreatMatch OAuth2 client secret. |
| CONNECTOR_NAME | `string` |  | string |  | `"ThreatMatch"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["threatmatch"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | Polling frequency as an ISO-8601 duration (e.g., 'P1D'). |
| THREATMATCH_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://eu.threatmatch.com/"` | Base URL of the ThreatMatch API. |
| THREATMATCH_IMPORT_FROM_DATE | `string` |  | [`^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z\|[+-]\d{2}(?::?\d{2})?)?)?\|P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%5Cd%7B4%7D-%5Cd%7B2%7D-%5Cd%7B2%7D%28%3F%3A%5BT+%5D%5Cd%7B2%7D%3A%5Cd%7B2%7D%28%3F%3A%3A%5Cd%7B2%7D%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%5Cd%7B2%7D%28%3F%3A%3A%3F%5Cd%7B2%7D%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%2BY%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2BW%29%3F%28%3F%3A%5Cd%2BD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%2BH%29%3F%28%3F%3A%5Cd%2BM%29%3F%28%3F%3A%5Cd%2B%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | `"P30D"` | Relative ISO-8601 duration (e.g., 'P30D') used to set the first import window. Applied on the first run only. Defaults to 30 days ago from the current date. |
| THREATMATCH_IMPORT_PROFILES | `boolean` |  | boolean |  | `true` | Import the ThreatMatch profiles dataset. |
| THREATMATCH_IMPORT_ALERTS | `boolean` |  | boolean |  | `true` | Import the ThreatMatch alerts dataset. |
| THREATMATCH_IMPORT_IOCS | `boolean` |  | boolean |  | `true` | Import the ThreatMatch IOCs dataset. |
| THREATMATCH_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` |  | `"amber"` | Default TLP marking applied when missing on source objects. |
| THREATMATCH_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean |  | `true` | Map ThreatMatch threat-actor objects to STIX intrusion-set. |
| THREATMATCH_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. (removal scheduled for 2027-01-01) |
