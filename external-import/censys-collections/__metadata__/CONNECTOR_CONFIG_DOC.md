# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CENSYS_COLLECTIONS_ORGANISATION_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Censys organisation ID. |
| CENSYS_COLLECTIONS_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Censys API token. |
| CONNECTOR_NAME | `string` |  | string | `"Censys Collections"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "X509-Certificate", "Malware", "Threat-Actor-Group", "Vulnerability", "Indicator"]` | The entity types this connector ingests into OpenCTI. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | How long to wait between two ingestion runs. |
| CENSYS_COLLECTIONS_COLLECTION_IDS | `array` |  | string | `null` | Comma-separated list of Censys collection IDs to ingest. Leave empty to ingest all collections for the organisation. Takes precedence over 'excluded_collection_ids' if both are set. |
| CENSYS_COLLECTIONS_EXCLUDED_COLLECTION_IDS | `array` |  | string | `null` | Comma-separated list of Censys collection IDs to exclude from ingestion; every other collection visible to the organisation is ingested. Ignored if 'collection_ids' is set. |
| CENSYS_COLLECTIONS_TLP_LEVEL | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | TLP marking applied to all ingested observables and indicators. |
| CENSYS_COLLECTIONS_INDICATOR_SCORE | `integer` |  | Between `0` and `100` | `50` | Confidence score (0–100) assigned to ingested observables and indicators. |
| CENSYS_COLLECTIONS_AUTO_INDICATOR_BY_SCORE | `boolean` |  | boolean | `false` | If enabled, an indicator is only auto-created for an observable when its score meets or exceeds 'indicator_score_threshold'. If disabled (default), an indicator is always auto-created for every ingested observable, regardless of score. |
| CENSYS_COLLECTIONS_INDICATOR_SCORE_THRESHOLD | `integer` |  | Between `0` and `100` | `50` | Minimum score (0–100) an observable must have for an indicator to be auto-created. Only used when 'auto_indicator_by_score' is enabled. |
| CENSYS_COLLECTIONS_REQUEST_TIMEOUT_SECONDS | `integer` |  | Minimum `1` | `60` | Per-request timeout (in seconds) for calls to the Censys API. Increase this if large collections cause read timeouts. |

