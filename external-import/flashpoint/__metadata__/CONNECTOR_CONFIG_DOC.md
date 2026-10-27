# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| FLASHPOINT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key to connect to Flashpoint. |
| CONNECTOR_NAME | `string` |  | string | `"Flashpoint"` | The name of the connector. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["flashpoint"]` | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| FLASHPOINT_IMPORT_START_DATE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | The date from which to start importing data, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago). |
| FLASHPOINT_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Whether to import reports from Flashpoint or not. |
| FLASHPOINT_GUESS_RELATIONSHIPS_FROM_REPORTS | `boolean` |  | boolean | `false` | Whether to guess relationships between entities or not. |
| FLASHPOINT_IMPORT_INDICATORS | `boolean` |  | boolean | `true` | Whether to import indicators of compromise (IoCs) or not. |
| FLASHPOINT_IMPORT_EXTRACTED_CONFIG_DOMAINS_URLS | `boolean` |  | boolean | `false` | Whether to create Domain-Name and URL observables from the network endpoints of extracted malware configurations. Disabled by default: these lists can mix real C2 servers with legitimate domains (false positives). |
| FLASHPOINT_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import alert data from Flashpoint or not. |
| FLASHPOINT_ALERT_CREATE_RELATED_ENTITIES | `boolean` |  | boolean | `false` | Whether to create alert related Channel entity and Media-Content observable or not. |
| FLASHPOINT_IMPORT_COMMUNITIES | `boolean` |  | boolean | `false` | Whether to import community data or not. |
| FLASHPOINT_COMMUNITIES_QUERIES | `array` |  | string | `["cybersecurity", "cyberattack"]` | List of community queries to execute. |
| FLASHPOINT_IMPORT_CCM_ALERTS | `boolean` |  | boolean | `false` | Whether to import Compromised Credentials Monitoring alerts or not. |
| FLASHPOINT_FRESH_CCM_ALERTS_ONLY | `boolean` |  | boolean | `true` | Whether to import only fresh Compromised Credentials Monitoring alerts or all of them. |
| FLASHPOINT_INDICATOR_TLP | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:GREEN"` | TLP marking applied to imported indicators. |
