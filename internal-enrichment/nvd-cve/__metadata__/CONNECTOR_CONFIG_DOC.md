# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"NIST NVD CVE Enrichment"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Report", "Grouping", "Note", "Observed-Data", "Opinion", "Case-Incident", "Case-Rfi", "Case-Rft", "Task", "Feedback", "Incident", "Vulnerability"]` | The scope of STIX entities the connector enriches (Containers and Vulnerability). |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | Enables or disables automatic enrichment when an in-scope entity is ingested. |
| CONNECTOR_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP level of the entities the connector is allowed to enrich. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Determines the verbosity of the logs. |
| CVE_BASE_URL | `string` |  | string | `"https://services.nvd.nist.gov/rest/json/cves"` | URL for the CVE API. |
| CVE_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `""` | API Key for the CVE API (optional for low-volume testing, recommended for production rate limits). |
| CVE_CREATE_UNMATCHED_CVE | `boolean` |  | boolean | `true` | If set to `True`, create a minimal placeholder Vulnerability entity even if NVD has not published data for the extracted CVE ID yet. |
| CVE_CREATE_RELATIONSHIPS | `boolean` |  | boolean | `true` | If set to `True`, create `related-to` / `targets` relationships when linking extracted CVEs to containers or incidents in addition to `object_refs`. |
| CVE_IMPORT_SOFTWARE | `boolean` |  | boolean | `false` | ⚠️ WARNING: Enabling this option can lead to the ingestion of a VERY SIGNIFICANT volume of data into the platform. Each CVE may resolve to dozens of CPE matches, resulting in massive amounts of Software entities and relationships. Use with caution. If set to `True`, resolve CPEs associated with each CVE via the NVD CPE Match API and import them as Software objects with 'has' relationships to vulnerabilities. |
| CVE_CPE_HISTORY_INTERVAL | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P120D"` | When import_software is enabled, The interval specifies how far back in time to search for CPEs that were modified within that period. This helps limit the number of CPEs resolved and imported. Maximum interval is 120 days. ⚠️ WARNING: Null value will disable the time filter and may result in importing a very large number of CPEs. Use with caution. |
| CVE_CPE_MAX_CONCURRENCY | `integer` |  | `0 < x ` | `10` | Maximum number of concurrent CPE resolution tasks when import_software is enabled. |
| CVE_CVE_MAX_CONCURRENCY | `integer` |  | `0 < x ` | `50` | Maximum number of concurrent CVE processing workers (bounds queued tasks and bundle sends). |
| CVE_MAX_CVES_PER_ENTITY | `integer` |  | `0 < x ` | `100` | Maximum number of distinct CVE identifiers extracted and enriched from a single entity/container. |
