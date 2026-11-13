# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| OCD_DATALAKE_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Long Term Token used to access Datalake API, used by `OCD_IMPORT_DATALAKE`, `OCD_IMPORT_THREAT_LIBRARY`, `OCD_WORLDWATCH_IMPORT_INDICATORS` and `OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES`. If all of them are disabled, set a placeholder such as a random string or `NO_PASSWORD`. |
| OCD_WORLDWATCH_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | World Watch API key, used by `OCD_IMPORT_WORLDWATCH`. If it is disabled, set a placeholder such as a random string or `NO_PASSWORD`. |
| CONNECTOR_NAME | `string` |  | string |  | `"Orange Cyberdefense Cyber Threat Intelligence"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Orange-Cyberdefense"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT30M"` | The period of time to await between two runs of the connector (ISO 8601 duration, minimum 1 minute). |
| OCD_IMPORT_DATALAKE | `boolean` |  | boolean |  | `true` | Whether to ingest indicators collections from Datalake. |
| OCD_IMPORT_THREAT_LIBRARY | `boolean` |  | boolean |  | `true` | Whether to ingest the latest entries of the Datalake Threat Library (Malware, Intrusion Set, Tools, Attack Patterns, Vulnerabilities, ...). |
| OCD_IMPORT_WORLDWATCH | `boolean` |  | boolean |  | `true` | Whether to ingest World Watch reports. |
| OCD_DATALAKE_ENV | `string` |  | string |  | `"prod"` | Advanced setting - Datalake environment to use: `prod` or `preprod`. |
| OCD_DATALAKE_QUERIES | `string` |  | string |  | `null` | JSON array of Datalake search query hashes to ingest, e.g. `[{"query_hash":"<hash>","label":"<label>"}]`. Required when `OCD_IMPORT_DATALAKE` is enabled. |
| OCD_DATALAKE_CREATE_OBSERVABLES | `boolean` |  | boolean |  | `true` | Whether to create observables from indicators. |
| OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS | `boolean` |  | boolean |  | `true` | Whether to skip Datalake indicators that do not have any score. |
| OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS | `boolean` |  | boolean |  | `true` | Whether to skip Datalake indicators that are whitelisted. |
| OCD_DATALAKE_FALLBACK_SCORE | `integer` |  | integer |  | `0` | Score used for Datalake indicators without any score, when `OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS` is disabled. |
| OCD_DATALAKE_ADD_TAGS_AS_LABELS | `boolean` |  | boolean |  | `true` | Whether to add Datalake tags as labels to the imported indicators. |
| OCD_DATALAKE_ADD_SCORES_AS_LABELS | `boolean` |  | boolean |  | `true` | Whether to add Datalake threat scores as labels to the imported indicators. |
| OCD_DATALAKE_ADD_SCORE | `boolean` |  | boolean |  | `true` | Whether to add score to the imported indicators (overwrite existing). |
| OCD_DATALAKE_ADD_TLP | `boolean` |  | boolean |  | `true` | Whether to add a TLP marking to the imported indicators (overwrite existing). |
| OCD_DATALAKE_ADD_EXTREF | `boolean` |  | boolean |  | `true` | Whether to add external references to the imported indicators. |
| OCD_DATALAKE_ADD_SUMMARY | `boolean` |  | boolean |  | `true` | Whether to add a threat summary as a note to the imported indicators. |
| OCD_DATALAKE_ADD_RELATED | `boolean` |  | boolean |  | `true` | Whether to import objects from the Threat Library related to imported indicators, such as malwares, campaigns, etc. |
| OCD_DATALAKE_ADD_SIGHTINGS | `boolean` |  | boolean |  | `true` | Whether to import positive sightings from Datalake. |
| OCD_DATALAKE_ADD_CREATEDBY | `boolean` |  | boolean |  | `true` | Whether to add a reference to the 'Orange Cyberdefense' organization as author of OpenCTI objects. |
| OCD_DATALAKE_ZIP_FILE_PATH | `string` |  | string |  | `"/opt/opencti-connector-orange-cyberdefense/data"` | Advanced setting - Path where temporary ZIP files are saved. |
| OCD_DATALAKE_ZIP_FILE_DELETE | `boolean` |  | boolean |  | `true` | Advanced setting - Whether to delete temporary ZIP files after processing. |
| OCD_DATALAKE_CURATE_LABELS | `boolean` |  | boolean |  | `true` | Advanced setting - Adapt Datalake CTI tags as STIX labels. |
| OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean |  | `true` | Advanced setting - Transform Threat Actor objects from Datalake to Intrusion Set objects. |
| OCD_WORLDWATCH_IMPORT_INDICATORS | `boolean` |  | boolean |  | `true` | Whether to import indicators from Datalake related to imported reports. |
| OCD_WORLDWATCH_IMPORT_INDICATORS_LOOKBACK | `integer` |  | integer |  | `2592000` | Advanced setting - How far (in seconds) to look back for indicators related to imported reports, based on their update time. |
| OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES | `boolean` |  | boolean |  | `true` | Whether to import objects from the Threat Library related to imported reports, such as malwares, campaigns, etc. |
| OCD_WORLDWATCH_START_DATE | `string` |  | string |  | `"2026-01-01"` | Start date for the import of World Watch reports. |
| OCD_RESET_STATE | `boolean` |  | boolean |  | `false` | Advanced setting - Force the use of the start date from the config instead of the state saved in OpenCTI. |
| OCD_CREATE_OBSERVABLES | `boolean` |  | boolean | ⛔️ | `null` | Use OCD_DATALAKE_CREATE_OBSERVABLES instead. |
| OCD_IGNORE_UNSCORED_INDICATORS | `boolean` |  | boolean | ⛔️ | `null` | Use OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS instead. |
| OCD_IGNORE_WHITELISTED_INDICATORS | `boolean` |  | boolean | ⛔️ | `null` | Use OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS instead. |
| OCD_FALLBACK_SCORE | `integer` |  | integer | ⛔️ | `null` | Use OCD_DATALAKE_FALLBACK_SCORE instead. |
| OCD_CURATE_LABELS | `boolean` |  | boolean | ⛔️ | `null` | Use OCD_DATALAKE_CURATE_LABELS instead. |
| OCD_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean | ⛔️ | `null` | Use OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET instead. |
| OCD_IMPORT_WORLDWATCH_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Use OCD_WORLDWATCH_API_KEY instead. |
| OCD_IMPORT_WORLDWATCH_START_DATE | `string` |  | string | ⛔️ | `null` | Use OCD_WORLDWATCH_START_DATE instead. |
| OCD_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
