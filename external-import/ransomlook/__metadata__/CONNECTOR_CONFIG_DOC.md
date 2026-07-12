# Connector Configurations

JSON Schema missing a description, provide it using the `description` key in the root of the JSON document.

### Type: `object`

> ⚠️ Additional properties are not allowed.

| Property | Type | Required | Possible values | Deprecated | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |  |
| CONNECTOR_NAME | `string` |  | string |  | `"RansomLook"` | Connector display name. |  |
| CONNECTOR_SCOPE | `array` |  | string |  | `["artifact", "attack-pattern", "cryptocurrency-wallet", "ipv4-addr", "ipv6-addr", "identity", "indicator", "infrastructure", "intrusion-set", "threat-actor", "incident", "malware", "report", "note", "domain-name", "url", "relationship"]` | STIX entity types imported by the connector. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | Period between connector runs. |  |
| RANSOMLOOK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://www.ransomlook.io/api"` | RansomLook API base URL. |  |
| RANSOMLOOK_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Optional API key sent in the Authorization header. |  |
| RANSOMLOOK_LABELS | `array` |  | string |  | `["ransomware", "ransomlook"]` | Labels applied to imported entities. |  |
| RANSOMLOOK_MARKING_DEFINITION | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:CLEAR"` | TLP marking for imported data. |  |
| RANSOMLOOK_INITIAL_HISTORY_DAYS | `integer` |  | `1 <= x <= 3650` |  | `7` | Lookback used on the first connector run. |  |
| RANSOMLOOK_MAX_RESPONSE_SIZE_MB | `integer` |  | `1 <= x <= 256` |  | `32` | Maximum accepted size of one RansomLook API response in MiB. |  |
| RANSOMLOOK_MAX_RECORDS_PER_ENDPOINT | `integer` |  | `1 <= x <= 10000` |  | `1000` | Maximum top-level records accepted from one endpoint or collection, and nested torrent context values retained per group. |  |
| RANSOMLOOK_MAX_PAGES_PER_ENDPOINT | `integer` |  | `1 <= x <= 100` |  | `10` | Maximum pages requested from a paginated endpoint per run. |  |
| RANSOMLOOK_MAX_REQUESTS_PER_RUN | `integer` |  | `10 <= x <= 100000` |  | `2000` | Maximum physical RansomLook HTTP attempts in one run. |  |
| RANSOMLOOK_MAX_RUN_DURATION_SECONDS | `integer` |  | `60 <= x <= 86400` |  | `2700` | Wall-clock deadline shared by all RansomLook requests in a run. |  |
| RANSOMLOOK_WORK_RECONCILIATION_TIMEOUT_SECONDS | `integer` |  | `10 <= x <= 7200` |  | `900` | Maximum time to wait for OpenCTI workers to complete one logical delivery before retaining its cursor for replay. |  |
| RANSOMLOOK_MAX_OBJECTS_PER_BUNDLE | `integer` |  | `32 <= x <= 5000` |  | `500` | Maximum STIX objects in one dependency-complete input bundle. |  |
| RANSOMLOOK_MAX_OBJECTS_PER_RUN | `integer` |  | `100 <= x <= 200000` |  | `20000` | Maximum STIX objects accumulated during one connector run before undelivered claims are retained for retry. |  |
| RANSOMLOOK_MAX_BUNDLE_SIZE_MB | `integer` |  | `1 <= x <= 256` |  | `64` | Maximum serialized size of one dependency-complete input bundle in MiB before queue transport; must cover configured post evidence. |  |
| RANSOMLOOK_REPLAY_WINDOW_DAYS | `integer` |  | `0 <= x <= 6` |  | `1` | Days replayed before the claims cursor to collect late posts. |  |
| RANSOMLOOK_MAX_ARTIFACT_SIZE_MB | `integer` |  | `1 <= x <= 32` |  | `5` | Maximum decoded size of one screenshot or source Artifact in MiB. |  |
| RANSOMLOOK_MAX_ARTIFACTS_PER_CLAIM | `integer` |  | `1 <= x <= 20` |  | `2` | Maximum evidence Artifacts decoded for one victim claim. |  |
| RANSOMLOOK_MAX_ARTIFACTS_PER_LOCATION | `integer` |  | `1 <= x <= 20` |  | `2` | Maximum evidence Artifacts decoded for one actor location. |  |
| RANSOMLOOK_MAX_ARTIFACTS_PER_RUN | `integer` |  | `1 <= x <= 10000` |  | `300` | Maximum evidence Artifacts decoded during one connector run. |  |
| RANSOMLOOK_MAX_ARTIFACT_BYTES_PER_RUN_MB | `integer` |  | `1 <= x <= 4096` |  | `200` | Maximum total decoded evidence bytes per run, in MiB. |  |
| RANSOMLOOK_MAX_EVIDENCE_SERIALIZED_BYTES_PER_RUN_MB | `integer` |  | `1 <= x <= 16384` |  | `800` | Maximum aggregate base64 evidence bytes retained across Artifacts and Report files during one run, in MiB. |  |
| RANSOMLOOK_MAX_PENDING_CLAIMS | `integer` |  | `1 <= x <= 100000` |  | `5000` | Maximum incomplete claim records retained for bounded retry. |  |
| RANSOMLOOK_MAX_CLAIM_RETRIES | `integer` |  | `1 <= x <= 100` |  | `5` | Maximum retry attempts for incomplete claim detail or evidence. |  |
| RANSOMLOOK_MAX_PENDING_GROUPS | `integer` |  | `1 <= x <= 10000` |  | `1000` | Maximum actor-profile groups retained for bounded retry. |  |
| RANSOMLOOK_MAX_ENRICHMENT_RETRIES | `integer` |  | `1 <= x <= 100` |  | `5` | Maximum retry attempts for transient actor-profile enrichment. |  |
| RANSOMLOOK_RETRY_MAX_AGE_DAYS | `integer` |  | `1 <= x <= 365` |  | `30` | Maximum age of claim and enrichment retry work. |  |
| RANSOMLOOK_ENRICH_ACTOR_PROFILES | `boolean` |  | boolean |  | `true` | Enrich profiles for groups encountered in the claims window. |  |
| RANSOMLOOK_IMPORT_INFRASTRUCTURE | `boolean` |  | boolean |  | `true` | Import typed actor infrastructure for encountered groups. |  |
| RANSOMLOOK_IMPORT_SENSITIVE_INFRASTRUCTURE | `boolean` |  | boolean |  | `false` | Import private, chat, admin, and file-server location values. |  |
| RANSOMLOOK_IMPORT_POST_EVIDENCE | `boolean` |  | boolean |  | `true` | Import bounded screenshot and HTML evidence attached to claims. |  |
| RANSOMLOOK_IMPORT_LOCATION_EVIDENCE | `boolean` |  | boolean |  | `false` | Import bounded captures attached to actor infrastructure. |  |
| RANSOMLOOK_IMPORT_NOTES | `boolean` |  | boolean |  | `true` | Import ransom notes associated with encountered groups. |  |
| RANSOMLOOK_IMPORT_WALLETS | `boolean` |  | boolean |  | `true` | Import cryptocurrency wallets associated with encountered groups. |  |
| RANSOMLOOK_IMPORT_TORRENTS | `boolean` |  | boolean |  | `true` | Import bounded torrent and magnet intelligence. |  |
| RANSOMLOOK_IMPORT_TORRENT_PEERS | `boolean` |  | boolean |  | `false` | Import torrent peer telemetry as context; never as Indicators. |  |
| RANSOMLOOK_IMPORT_LEAKS | `boolean` |  | boolean |  | `true` | Import deterministically related leak evidence. |  |
| RANSOMLOOK_IMPORT_ANALYSES | `boolean` |  | boolean |  | `true` | Import explicit technical analyses, malware, and TTP mappings. |  |
| RANSOMLOOK_IMPORT_VICTIM_WEBSITES | `boolean` |  | boolean |  | `true` | Import victim website observables as non-malicious context. |  |
| RANSOMLOOK_CREATE_INDICATORS | `boolean` |  | boolean |  | `false` | Create Indicators only for explicit upstream malicious assertions. |  |
