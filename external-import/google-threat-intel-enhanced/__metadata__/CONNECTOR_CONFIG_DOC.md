# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| GTI_API_KEY | `string` | ✅ | string |  |  |
| CONNECTOR_NAME | `string` |  | string | `"Google Threat Intel Feeds"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["report", "location", "identity", "attack_pattern", "domain", "file", "ipv4", "ipv6", "malware", "sector", "intrusion_set", "url", "vulnerability"]` | The scope of the connector, e.g. 'indicator, vulnerability'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT2H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | integer | `500` | Maximum number of messages in the connector queue before throttling. |
| CONNECTOR_TLP_LEVEL | `string` |  | `WHITE` `GREEN` `AMBER` `RED` `WHITE+STRICT` `GREEN+STRICT` `AMBER+STRICT` `RED+STRICT` | `"AMBER+STRICT"` | Traffic Light Protocol (TLP) marking for imported data. |
| CONNECTOR_ENRICHMENT_RESOLUTION | `string` |  | string | `"PT1M"` | ISO 8601 duration between enrichment scheduler checks. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `null` |  |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `null` |  |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `null` |  |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` |  |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | integer | `null` |  |
| GTI_IMPORT_START_DATE | `string` |  | string | `"P1D"` |  |
| GTI_API_URL | `string` |  | string | `"https://www.virustotal.com/api/v3"` |  |
| GTI_X_TOOL | `string` |  | string | `"OpenCTI.GTIConnector.v1.0"` |  |
| GTI_IMPORT_REPORTS | `boolean` |  | boolean | `true` |  |
| GTI_IMPORT_CAMPAIGNS | `boolean` |  | boolean | `false` |  |
| GTI_IMPORT_THREAT_ACTORS | `boolean` |  | boolean | `false` |  |
| GTI_IMPORT_MALWARE_FAMILIES | `boolean` |  | boolean | `false` |  |
| GTI_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `false` |  |
| GTI_REPORT_TYPES | `array` |  | string | `["All"]` |  |
| GTI_ORIGINS | `array` |  | string | `["All"]` |  |
| GTI_CAMPAIGN_ORIGINS | `array` |  | string | `["google threat intelligence"]` |  |
| GTI_THREAT_ACTOR_ORIGINS | `array` |  | string | `["google threat intelligence"]` |  |
| GTI_MALWARE_FAMILY_ORIGINS | `array` |  | string | `["google threat intelligence"]` |  |
| GTI_VULNERABILITY_ORIGINS | `array` |  | string | `["google threat intelligence"]` |  |
| GTI_INDICATOR_SCORING | `string` |  | string | `"gti_derived"` |  |
| GTI_ENRICH_IOCS_WITH_THREAT_ACTORS_AND_MALWARE | `boolean` |  | boolean | `false` |  |
| GTI_IOC_ENRICHMENT_THRESHOLD | `integer` |  | integer | `250` |  |
