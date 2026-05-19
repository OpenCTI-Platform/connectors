# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| ALIENVAULT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The OTX Key. |
| CONNECTOR_NAME | `string` |  | string |  | `"AlienVault"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["alienvault"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT30M"` | The period of time to await between two runs of the connector. |
| ALIENVAULT_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://otx.alienvault.com"` | The base URL for the OTX DirectConnect API. |
| ALIENVAULT_TLP | `string` |  | string |  | `"White"` | The default TLP marking used if the Pulse does not define TLP. |
| ALIENVAULT_CREATE_OBSERVABLES | `boolean` |  | boolean |  | `true` | If true then observables will be created from Pulse indicators and added to the report. |
| ALIENVAULT_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | If true then indicators will be created from Pulse indicators and added to the report. |
| ALIENVAULT_PULSE_START_TIMESTAMP | `string` |  | string |  | `"2020-05-01T00:00:00"` | The Pulses modified after this timestamp will be imported. Timestamp in ISO 8601 format, UTC. |
| ALIENVAULT_REPORT_TYPE | `string` |  | string |  | `"threat-report"` | The type of imported reports in the OpenCTI. |
| ALIENVAULT_REPORT_STATUS | `string` |  | string |  | `"New"` | The status of imported reports in the OpenCTI. |
| ALIENVAULT_GUESS_MALWARE | `boolean` |  | boolean |  | `false` | The Pulse tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Pulse. |
| ALIENVAULT_GUESS_CVE | `boolean` |  | boolean |  | `false` | The Pulse tags are used to guess (checks whether tag matches (CVE-\d{4}-\d{4,7})) vulnerabilities. |
| ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES | `array` |  | string |  | `[]` | The Pulse indicator types that will be excluded from the import. |
| ALIENVAULT_ENABLE_RELATIONSHIPS | `boolean` |  | boolean |  | `true` | If true then the relationships will be created between SDOs. |
| ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES | `boolean` |  | boolean |  | `true` | If true then the relationships `indicates` will be created between indicators and attack patterns. |
| ALIENVAULT_FILTER_INDICATORS | `boolean` |  | boolean |  | `false` | This boolean filters out indicators created before the latest pulse datetime, ensuring only recent indicators are processed. |
| ALIENVAULT_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer |  | `50` | The default x_opencti_score to use for indicators. If a per indicator type score is not set, this is used. |
| ALIENVAULT_X_OPENCTI_SCORE_IP | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for IP indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_DOMAIN | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for Domain indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_HOSTNAME | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for Hostname indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_EMAIL | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for Email indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_FILE | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for StixFile indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_URL | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for URL indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_MUTEX | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for Mutex indicators. |
| ALIENVAULT_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET | `integer` |  | integer |  | `null` | (Optional): The x_opencti_score to use for Cryptocurrency Wallet indicators. |
| ALIENVAULT_INTERVAL_SEC | `integer` |  | integer | ⛔️ | `1800` | The interval in seconds between each run of the connector. |
