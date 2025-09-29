# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CROWDSTRIKE_CLIENT_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CrowdStrike API client ID for authentication. |
| CROWDSTRIKE_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CrowdStrike API client secret for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdStrike"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crowdstrike"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_DURATION_PERIOD | `string` |  | string | `"PT1H"` | ISO8601 Duration format starting with 'P' for Period (e.g., 'PT30M' for 30 minutes). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CROWDSTRIKE_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.crowdstrike.com"` | CrowdStrike API base URL. |
| CROWDSTRIKE_TLP | `string` |  | `red` `amber+strict` `amber` `green` `clear` | `"amber+strict"` | Default Traffic Light Protocol (TLP) marking for imported data. |
| CROWDSTRIKE_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create observables in OpenCTI. |
| CROWDSTRIKE_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Whether to create indicators in OpenCTI. |
| CROWDSTRIKE_SCOPES | `array` |  | string | `["actor", "report", "indicator", "yara_master", "snort_suricata_master"]` | Comma-separated list of scopes to enable. Available: actor, report, indicator, yara_master, snort_suricata_master. |
| CROWDSTRIKE_ACTOR_START_TIMESTAMP | `integer` |  | integer | `0` | Unix timestamp from which to start importing actors. BEWARE: 0 means ALL actors! |
| CROWDSTRIKE_REPORT_START_TIMESTAMP | `integer` |  | integer |  | Unix timestamp from which to start importing reports. Default is 30 days ago. BEWARE: 0 means ALL reports! |
| CROWDSTRIKE_REPORT_STATUS | `string` |  | `New` `In Progress` `Analyzed` `Closed` | `"New"` | Report status filter. |
| CROWDSTRIKE_REPORT_INCLUDE_TYPES | `array` |  | string | `["notice", "tipper", "intelligence report", "periodic report"]` | Comma-separated list of report types to include. |
| CROWDSTRIKE_REPORT_TYPE | `string` |  | string | `"threat-report"` | OpenCTI report type for imported reports. |
| CROWDSTRIKE_REPORT_TARGET_INDUSTRIES | `array` |  | string | `null` | Comma-separated list of target industries to filter reports. |
| CROWDSTRIKE_REPORT_GUESS_MALWARE | `boolean` |  | boolean | `false` | Whether to use report tags to guess related malware. |
| CROWDSTRIKE_INDICATOR_START_TIMESTAMP | `integer` |  | integer |  | Unix timestamp from which to start importing indicators. Default is 30 days ago. BEWARE: 0 means ALL indicators! |
| CROWDSTRIKE_INDICATOR_EXCLUDE_TYPES | `array` |  | string | `["hash_ion", "hash_md5", "hash_sha1", "password", "username"]` | Comma-separated list of indicator types to exclude from import. |
| CROWDSTRIKE_DEFAULT_X_OPENCTI_SCORE | `integer` |  | `0 < x ` | `50` | Default confidence score for entities without explicit score. |
| CROWDSTRIKE_INDICATOR_LOW_SCORE | `integer` |  | `0 < x ` | `40` | Score assigned to indicators with low confidence labels. |
| CROWDSTRIKE_INDICATOR_LOW_SCORE_LABELS | `array` |  | string | `["MaliciousConfidence/Low"]` | Comma-separated list of labels indicating low confidence. |
| CROWDSTRIKE_INDICATOR_MEDIUM_SCORE | `integer` |  | `0 < x ` | `60` | Score assigned to indicators with medium confidence labels. |
| CROWDSTRIKE_INDICATOR_MEDIUM_SCORE_LABELS | `array` |  | string | `["MaliciousConfidence/Medium"]` | Comma-separated list of labels indicating medium confidence. |
| CROWDSTRIKE_INDICATOR_HIGH_SCORE | `integer` |  | `0 < x ` | `80` | Score assigned to indicators with high confidence labels. |
| CROWDSTRIKE_INDICATOR_HIGH_SCORE_LABELS | `array` |  | string | `["MaliciousConfidence/High"]` | Comma-separated list of labels indicating high confidence. |
| CROWDSTRIKE_INDICATOR_UNWANTED_LABELS | `array` |  | string | `null` | Comma-separated list of unwanted labels to filter out indicators. Can be used to filter low confidence indicators: 'MaliciousConfidence/Low,MaliciousConfidence/Medium'. |
| CROWDSTRIKE_NO_FILE_TRIGGER_IMPORT | `boolean` |  | boolean | `true` | Whether to trigger import without file dependencies. |
| CROWDSTRIKE_INTERVAL_SEC | `integer` |  | `0 < x ` | `1800` | Polling interval in seconds for fetching data (used when duration_period is not set). |
