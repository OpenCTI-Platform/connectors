# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| POLYSWARM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | PolySwarm API key for authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"PolySwarm Sandbox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Artifact", "StixFile", "Url"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| POLYSWARM_API_URL | `string` |  | string |  | `"https://api.polyswarm.network"` | PolySwarm API base URL. |
| POLYSWARM_COMMUNITY | `string` |  | string |  | `"default"` | PolySwarm community (default or private). |
| POLYSWARM_ALLOW_PUBLIC_COMMUNITY | `boolean` |  | boolean |  | `false` | Allow file uploads to the public PolySwarm community ('default'). Uploaded files become visible to the PolySwarm community, so this is off by default: set POLYSWARM_COMMUNITY to your private community, or set this to true to submit publicly. |
| POLYSWARM_TIMEOUT | `integer` |  | integer |  | `30` | HTTP timeout for PolySwarm API calls in seconds. |
| POLYSWARM_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean |  | `true` | If false, keep higher existing score instead of overwriting. |
| POLYSWARM_SANDBOX_ENABLED | `boolean` |  | boolean |  | `true` | Enable sandbox analysis in addition to scan. |
| POLYSWARM_SANDBOX_PROVIDER | `string` |  | string |  | `"cape"` | Sandbox provider: cape, triage, or both. |
| POLYSWARM_SANDBOX_VM_CAPE | `string` |  | string |  | `"win-10-build-19041"` | VM slug for Cape sandbox submissions. |
| POLYSWARM_SANDBOX_VM_TRIAGE | `string` |  | string |  | `"windows11-21h2-x64"` | VM slug for Triage sandbox submissions. |
| POLYSWARM_SANDBOX_VM | `string` |  | string |  | `null` | Legacy single VM slug (overrides per-provider if set). |
| POLYSWARM_SANDBOX_NETWORK_ENABLED | `boolean` |  | boolean |  | `true` | Enable internet access during sandbox analysis. |
| POLYSWARM_SANDBOX_TIMEOUT | `integer` |  | integer |  | `600` | Maximum wait time for sandbox results in seconds. |
| POLYSWARM_SANDBOX_URL_SEND_QUERY | `boolean` |  | boolean |  | `false` | Send a Url observable's query string and fragment to PolySwarm for detonation. Off by default: only scheme, host and path are submitted, so tokens in a query string never leave OpenCTI. |
| POLYSWARM_SANDBOX_LOOKUP_MAX_AGE_DAYS | `integer` |  | `0 <= x ` |  | `0` | Hash lookup (StixFile observables) and report reuse (Artifacts): an existing PolySwarm sandbox report older than this many days is treated as missing. 0 means a report of any age is used. |
| POLYSWARM_SANDBOX_REUSE_REPORT | `boolean` |  | boolean |  | `false` | For an Artifact, look for an existing PolySwarm sandbox report by SHA-256 before uploading. When every configured provider has a usable report, it is used and the file is not uploaded again (the scan result is also taken from the latest existing scan of the hash). |
| POLYSWARM_SANDBOX_DETONATE_BY_HASH | `boolean` |  | boolean |  | `false` | For a StixFile observable with no usable existing report, detonate the sample PolySwarm already holds for that hash. Nothing is uploaded from OpenCTI, but each detonation spends sandbox credits and runs in the community set in POLYSWARM_COMMUNITY. Off by default. |
| POLYSWARM_SANDBOX_MAX_DROPPED_FILES | `integer` |  | `0 <= x ` |  | `25` | Maximum dropped files per detonation to create as File observables related to the detonated observable (0 turns it off). Uses data already in the sandbox report. |
| POLYSWARM_SANDBOX_C2_INDICATORS | `boolean` |  | boolean |  | `true` | Create Indicators (valid 30 days) for command and control addresses the sandbox report lists in an extracted malware configuration. Observables are created either way; needs create_indicators. |
| POLYSWARM_SANDBOX_ATTACH_PCAP | `boolean` |  | boolean |  | `false` | Download the sandbox network capture (pcap) and attach it to the observable. Off by default: it is an extra download per detonation. |
| POLYSWARM_SANDBOX_PCAP_MAX_SIZE | `integer` |  | `1 <= x ` |  | `26214400` | Largest pcap in bytes to attach (default 25MB). Larger captures are skipped. |
| POLYSWARM_POLL_INTERVAL | `integer` |  | integer |  | `30` | Seconds between poll attempts for scan/sandbox results. |
| POLYSWARM_POLL_TIMEOUT | `integer` |  | integer |  | `900` | Maximum wait time for scan results in seconds. |
| POLYSWARM_JSON_REPORT_ENABLED | `boolean` |  | boolean |  | `true` | Attach raw JSON scan/sandbox data as a file. |
| POLYSWARM_PDF_REPORT_ENABLED | `boolean` |  | boolean |  | `true` | Request and attach PDF report from PolySwarm. |
| POLYSWARM_LLM_REPORT_ENABLED | `boolean` |  | boolean |  | `false` | Request AI-generated analysis summary (opt-in). |
| POLYSWARM_LLM_REPORT_TIMEOUT | `integer` |  | integer |  | `120` | Maximum wait time for LLM report in seconds. |
| POLYSWARM_MIN_POLYSCORE | `integer` |  | integer |  | `50` | Minimum PolyScore (0-100) to create indicators. |
| POLYSWARM_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | Create STIX Indicator objects from scan results. |
| POLYSWARM_CREATE_OBSERVABLES | `boolean` |  | boolean |  | `true` | Create STIX Observable objects from sandbox IOCs. |
| POLYSWARM_MAX_FILE_SIZE | `integer` |  | integer |  | `33554432` | Maximum file size in bytes (default 32MB). |
| POLYSWARM_DOWNLOAD_ARTIFACTS | `boolean` |  | boolean |  | `true` | Download file artifacts from OpenCTI for scanning. |
| POLYSWARM_QUOTA_WARN_BELOW | `integer` |  | `0 <= x ` |  | `100` | Log a warning when the remaining daily API quota, or a sandbox or hunt allowance, falls below this number (0 = no warnings). Accounts with no cap are never warned. |
| POLYSWARM_POLYKG_API_URL | `string` |  | string |  | `null` | polykg REST API URL for malware profile enrichment (empty = disabled). |
| POLYSWARM_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
