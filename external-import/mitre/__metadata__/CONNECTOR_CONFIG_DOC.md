# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"Mitre Att&ck"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"tool,report,malware,identity,campaign,intrusion-set,attack-pattern,course-of-action,x-mitre-data-source,x-mitre-data-component,x-mitre-matrix,x-mitre-tactic,x-mitre-collection"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT24H"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | `0 < x ` | `null` | Connector queue max size in Mbytes. Default to 500. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `null` | Connector run-and-terminate flag. |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `null` | Connector send-to-queue flag. |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `null` | Connector send-to-directory flag. |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` | Connector send-to-directory path. |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | `0 < x ` | `null` | Connector send-to-directory retention in days. |
| MITRE_REMOVE_STATEMENT_MARKING | `boolean` |  | boolean | `false` | Whether to remove statement markings from the ingested MITRE data. Useful when marking metadata is unnecessary or interferes with processing. |
| MITRE_ENTERPRISE_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"` | URL to the MITRE ATT&CK Enterprise JSON file. This dataset includes tactics, techniques, and procedures (TTPs) for enterprise IT environments. |
| MITRE_MOBILE_ATTACK_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"` | URL to the MITRE Mobile ATT&CK JSON file. Contains mobile-specific attack techniques and mappings. |
| MITRE_ICS_ATTACK_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"` | URL to the MITRE ICS ATT&CK JSON file. Pertains to attack techniques targeting industrial control systems. |
| MITRE_CAPEC_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"` | URL to the CAPEC (Common Attack Pattern Enumeration and Classification) JSON file. Provides a comprehensive dictionary of known attack patterns used by adversaries. |
