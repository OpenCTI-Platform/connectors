# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"MITRE ATT&CK"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["tool", "report", "malware", "identity", "campaign", "intrusion-set", "attack-pattern", "course-of-action", "x-mitre-data-source", "x-mitre-data-component", "x-mitre-matrix", "x-mitre-tactic", "x-mitre-collection"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| MITRE_REMOVE_STATEMENT_MARKING | `boolean` |  | boolean | `false` | Whether to remove statement markings from the ingested MITRE data. Useful when marking metadata is unnecessary or interferes with processing. |
| MITRE_INTERVAL | `integer` |  | `0 < x ` | `7` | Polling interval in days for fetching and refreshing MITRE data. Determines how often the system checks for updates to ATT&CK datasets. |
| MITRE_ENTERPRISE_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"` | URL to the MITRE ATT&CK Enterprise JSON file. This dataset includes tactics, techniques, and procedures (TTPs) for enterprise IT environments. |
| MITRE_MOBILE_ATTACK_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"` | URL to the MITRE Mobile ATT&CK JSON file. Contains mobile-specific attack techniques and mappings. |
| MITRE_ICS_ATTACK_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"` | URL to the MITRE ICS ATT&CK JSON file. Pertains to attack techniques targeting industrial control systems. |
| MITRE_CAPEC_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"` | URL to the CAPEC (Common Attack Pattern Enumeration and Classification) JSON file. Provides a comprehensive dictionary of known attack patterns used by adversaries. |
