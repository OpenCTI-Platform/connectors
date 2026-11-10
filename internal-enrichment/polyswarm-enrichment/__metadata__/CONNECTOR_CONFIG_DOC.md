# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| POLYSWARM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | PolySwarm API key for authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"PolySwarm Hash Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["StixFile", "Artifact", "Url", "Domain-Name", "IPv4-Addr", "IPv6-Addr"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"red"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| POLYSWARM_COMMUNITY | `string` |  | string |  | `"default"` | PolySwarm community ('default' or 'private' for dual-community). |
| POLYSWARM_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean |  | `true` | If false, keep higher existing score instead of overwriting. |
| POLYSWARM_MAX_POLLING_TIME | `integer` |  | integer |  | `120` | Maximum wait time for scan results in seconds. |
| POLYSWARM_IOC_ENABLED | `boolean` |  | boolean |  | `true` | Enable network IOC extraction from PolySwarm IOC API. |
| POLYSWARM_IOC_MAX_COUNT | `integer` |  | integer |  | `20` | Max network IOC observables per enrichment (global cap). |
| POLYSWARM_IOC_SCORE | `integer` |  | integer |  | `20` | x_opencti_score for network IOC observables. |
| POLYSWARM_IOC_TYPES | `array` |  | string |  | `["ip", "domain", "url"]` | Which IOC types to create (comma-separated: ip,domain,url). |
| POLYSWARM_RESCAN_OLDER_THAN_DAYS | `integer` |  | `0 <= x ` |  | `0` | Ask PolySwarm to rescan a sample it already holds when its latest scan is older than this many days, or when it has no completed scan (0 = never rescan). Each rescan spends PolySwarm scan quota. Nothing is uploaded: PolySwarm rescans its own copy of the sample. |
| POLYSWARM_RESCAN_TIMEOUT | `integer` |  | `1 <= x ` |  | `300` | Maximum seconds to wait for a rescan to finish. On timeout the enrichment uses the previous scan result and says so in the note. |
| POLYSWARM_DOWNLOAD_SAMPLE | `boolean` |  | boolean |  | `false` | Download the sample for a File PolySwarm holds and store it as an Artifact in OpenCTI. This puts LIVE MALWARE in OpenCTI file storage and spends PolySwarm download quota. Off by default. |
| POLYSWARM_DOWNLOAD_MAX_SIZE_MB | `integer` |  | `1 <= x ` |  | `20` | Largest sample, in MB, that will be downloaded. Larger samples are skipped and the note says so. |
| POLYSWARM_NETWORK_RELATED_FILES_MAX | `integer` |  | `0 <= x ` |  | `10` | Max related file hashes to import when enriching an IP or domain observable (0 = disabled). |
| POLYSWARM_NETWORK_URL_SEND_QUERY | `boolean` |  | boolean |  | `false` | Send a URL observable's query string and fragment to PolySwarm. Off by default: only scheme, host and path are looked up, so tokens in a query string never leave OpenCTI. |
| POLYSWARM_NETWORK_INDICATOR_MIN_DETECTIONS | `integer` |  | `1 <= x ` |  | `2` | Minimum malicious engine detections on a URL, domain or IP scan before an Indicator is created. |
| POLYSWARM_QUOTA_WARN_BELOW | `integer` |  | `0 <= x ` |  | `100` | Log a warning when the remaining daily API quota, or a sandbox or hunt allowance, falls below this number (0 = no warnings). Accounts with no cap are never warned. |
| POLYSWARM_PIVOT_IMPHASH_MAX | `integer` |  | `0 <= x <= 100` |  | `0` | Max other files with the same imphash to import when enriching a file PolySwarm reports a PE imphash for (0 = off, e.g. 10). Imported files are labelled polyswarm-pivot-result and never pivot again. |
| POLYSWARM_PIVOT_TTP_MAX | `integer` |  | `0 <= x <= 100` |  | `0` | Max files to import when enriching an Attack-Pattern with a MITRE ATT&CK id (0 = off, e.g. 10). Any value above 0 adds Attack-Pattern to the default connector scope; if you set CONNECTOR_SCOPE yourself, add Attack-Pattern to it or OpenCTI will not offer this connector for Attack-Patterns. Runs only with CONNECTOR_AUTO=false: with auto enrichment on, every Attack-Pattern created would trigger a search. |
| POLYSWARM_YARA_HUNT_ENABLED | `boolean` |  | boolean |  | `false` | Run a PolySwarm historical hunt for each YARA Indicator that is enriched. Writes to your PolySwarm account (creates hunts), spends hunt quota, and sends the YARA rule text to PolySwarm. Adds Indicator to the default connector scope; if you set CONNECTOR_SCOPE yourself, add Indicator to it or OpenCTI will not offer this connector for Indicators. |
| POLYSWARM_YARA_HUNT_WINDOW_DAYS | `integer` |  | integer |  | `30` | How many days back a hunt reaches: 30, 60, 90 or 180. |
| POLYSWARM_YARA_HUNT_TIMEOUT | `integer` |  | `60 <= x ` |  | `300` | Seconds to wait for a hunt before reporting it as still running (hunts can be slow). |
| POLYSWARM_YARA_HUNT_MAX_RESULTS | `integer` |  | `1 <= x <= 1000` |  | `50` | Max matched files imported as File observables per hunt. |
| POLYSWARM_POLYKG_API_URL | `string` |  | string |  | `""` | polykg REST API URL for malware profile enrichment (empty = disabled). |
| POLYSWARM_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
