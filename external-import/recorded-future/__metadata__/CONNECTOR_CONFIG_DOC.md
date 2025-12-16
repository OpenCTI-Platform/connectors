# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| RECORDED_FUTURE_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Recorded Future API token for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"Recorded Future"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["ipv4-addr", "ipv6-addr", "vulnerability", "domain", "url", "file-sha256", "file-md5", "file-sha1"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_DURATION_PERIOD | `string` |  | string | `"PT24H"` | ISO8601 Duration format starting with 'P' for Period (e.g., 'PT24H' for 24 hours). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| RECORDED_FUTURE_INITIAL_LOOKBACK | `integer` |  | `0 < x ` | `240` | Initial lookback period in hours when first running the connector. |
| RECORDED_FUTURE_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Default Traffic Light Protocol (TLP) marking for imported data. |
| RECORDED_FUTURE_INTERVAL | `integer` |  | `0 < x ` | `1` | Polling interval in hours for fetching Recorded Future data. |
| RECORDED_FUTURE_PULL_ANALYST_NOTES | `boolean` |  | boolean | `true` | Whether to import Recorded Future analyst notes. |
| RECORDED_FUTURE_LAST_PUBLISHED_NOTES | `integer` |  | `0 < x ` | `24` | Time window in hours for fetching recently published analyst notes. |
| RECORDED_FUTURE_TOPIC | `array` |  | string | `["VTrvnW", "g1KBGI", "ZjnoP0", "aDKkpk", "TXSFt5", "UrMRnT", "TXSFt3"]` | Comma-separated list of topic IDs to filter analyst notes. Examples: VTrvnW (Yara Rule), g1KBGI (Sigma Rule), ZjnoP0 (Snort Rule), aDKkpk (TTP Instance), TXSFt5 (Validated Intelligence Event), UrMRnT (Informational), TXSFt3 (Threat Lead). |
| RECORDED_FUTURE_INSIKT_ONLY | `boolean` |  | boolean | `true` | Whether to import only Insikt notes (Recorded Future's analyst reports). |
| RECORDED_FUTURE_PULL_SIGNATURES | `boolean` |  | boolean | `false` | Whether to import detection signatures (Yara/Snort/Sigma rules) from analyst notes. |
| RECORDED_FUTURE_PERSON_TO_TA | `boolean` |  | boolean | `false` | Whether to convert Person entities to Threat Actor entities. |
| RECORDED_FUTURE_TA_TO_INTRUSION_SET | `boolean` |  | boolean | `false` | Whether to convert Threat Actor entities to Intrusion Set entities. |
| RECORDED_FUTURE_RISK_AS_SCORE | `boolean` |  | boolean | `true` | Whether to import risk scores as confidence scores in OpenCTI. |
| RECORDED_FUTURE_RISK_THRESHOLD | `integer` |  | `0 < x ` | `60` | Minimum risk score threshold (0-100) for importing entities. |
| RECORDED_FUTURE_ANALYST_NOTES_GUESS_RELATIONSHIPS | `boolean` |  | boolean | `false` | Enable or disable the automatic guessing of relationships between entities when processing analyst notes. |
| RECORDED_FUTURE_PULL_RISK_LIST | `boolean` |  | boolean | `false` | Whether to import Recorded Future risk lists. |
| RECORDED_FUTURE_RISKRULES_AS_LABEL | `boolean` |  | boolean | `false` | Whether to import risk rules as labels in OpenCTI. |
| RECORDED_FUTURE_RISK_LIST_THRESHOLD | `integer` |  | `0 < x ` | `70` | Minimum risk score threshold (0-100) for importing risk list entities. |
| RECORDED_FUTURE_RISKLIST_RELATED_ENTITIES | `array` |  | string | `["Malware", "Hash", "URL", "Threat Actor", "MitreAttackIdentifier"]` | Comma-separated list of entity types to import from risk lists. Available choices: Malware, Hash, URL, Threat Actor, MitreAttackIdentifier. |
| RECORDED_FUTURE_PULL_THREAT_MAPS | `boolean` |  | boolean | `false` | Whether to import Threat Actors and Malware from Recorded Future threat maps. |
| ALERT_ENABLE | `boolean` |  | boolean | `false` | Whether to enable fetching Recorded Future alerts. |
| ALERT_DEFAULT_OPENCTI_SEVERITY | `string` |  | `low` `medium` `high` `critical` | `"low"` | Default severity level for alerts imported into OpenCTI. |
| ALERT_PRIORITY_ALERTS_ONLY | `boolean` |  | boolean | `false` | Whether to import only high-priority alerts. |
| PLAYBOOK_ALERT_ENABLE | `boolean` |  | boolean | `false` | Whether to enable fetching Recorded Future playbook alerts. |
| PLAYBOOK_ALERT_SEVERITY_THRESHOLD_DOMAIN_ABUSE | `string` |  | `Informational` `Moderate` `High` | `"Informational"` | Minimum severity threshold for domain abuse playbook alerts. |
| PLAYBOOK_ALERT_SEVERITY_THRESHOLD_IDENTITY_NOVEL_EXPOSURES | `string` |  | `Informational` `Moderate` `High` | `"Informational"` | Minimum severity threshold for identity novel exposures playbook alerts. |
| PLAYBOOK_ALERT_SEVERITY_THRESHOLD_CODE_REPO_LEAKAGE | `string` |  | `Informational` `Moderate` `High` | `"Informational"` | Minimum severity threshold for code repository leakage playbook alerts. |
| PLAYBOOK_ALERT_DEBUG | `boolean` |  | boolean | `false` | Whether to enable debug logging for playbook alerts. |
