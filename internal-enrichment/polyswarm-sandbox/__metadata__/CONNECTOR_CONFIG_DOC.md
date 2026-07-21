# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| POLYSWARM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | PolySwarm API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"PolySwarm Sandbox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| POLYSWARM_API_URL | `string` |  | string | `"https://api.polyswarm.network"` | PolySwarm API base URL. |
| POLYSWARM_COMMUNITY | `string` |  | string | `"default"` | PolySwarm community (default or private). |
| POLYSWARM_TIMEOUT | `integer` |  | integer | `30` | HTTP timeout for PolySwarm API calls in seconds. |
| POLYSWARM_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Max TLP level of entities to enrich. |
| POLYSWARM_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean | `true` | If false, keep higher existing score instead of overwriting. |
| POLYSWARM_SANDBOX_ENABLED | `boolean` |  | boolean | `true` | Enable sandbox analysis in addition to scan. |
| POLYSWARM_SANDBOX_PROVIDER | `string` |  | string | `"cape"` | Sandbox provider: cape, triage, or both. |
| POLYSWARM_SANDBOX_VM_CAPE | `string` |  | string | `"win-10-build-19041"` | VM slug for Cape sandbox submissions. |
| POLYSWARM_SANDBOX_VM_TRIAGE | `string` |  | string | `"windows11-21h2-x64"` | VM slug for Triage sandbox submissions. |
| POLYSWARM_SANDBOX_VM | `string` |  | string | `null` | Legacy single VM slug (overrides per-provider if set). |
| POLYSWARM_SANDBOX_NETWORK_ENABLED | `boolean` |  | boolean | `true` | Enable internet access during sandbox analysis. |
| POLYSWARM_SANDBOX_TIMEOUT | `integer` |  | integer | `600` | Maximum wait time for sandbox results in seconds. |
| POLYSWARM_POLL_INTERVAL | `integer` |  | integer | `30` | Seconds between poll attempts for scan/sandbox results. |
| POLYSWARM_POLL_TIMEOUT | `integer` |  | integer | `900` | Maximum wait time for scan results in seconds. |
| POLYSWARM_JSON_REPORT_ENABLED | `boolean` |  | boolean | `true` | Attach raw JSON scan/sandbox data as a file. |
| POLYSWARM_PDF_REPORT_ENABLED | `boolean` |  | boolean | `true` | Request and attach PDF report from PolySwarm. |
| POLYSWARM_LLM_REPORT_ENABLED | `boolean` |  | boolean | `false` | Request AI-generated analysis summary (opt-in). |
| POLYSWARM_LLM_REPORT_TIMEOUT | `integer` |  | integer | `120` | Maximum wait time for LLM report in seconds. |
| POLYSWARM_MIN_POLYSCORE | `integer` |  | integer | `50` | Minimum PolyScore (0-100) to create indicators. |
| POLYSWARM_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Create STIX Indicator objects from scan results. |
| POLYSWARM_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create STIX Observable objects from sandbox IOCs. |
| POLYSWARM_MAX_FILE_SIZE | `integer` |  | integer | `33554432` | Maximum file size in bytes (default 32MB). |
| POLYSWARM_DOWNLOAD_ARTIFACTS | `boolean` |  | boolean | `true` | Download file artifacts from OpenCTI for scanning. |
| POLYSWARM_POLYKG_API_URL | `string` |  | string | `null` | polykg REST API URL for malware profile enrichment (empty = disabled). |
