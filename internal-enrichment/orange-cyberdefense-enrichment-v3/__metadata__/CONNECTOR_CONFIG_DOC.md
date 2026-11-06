# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| OCD_ENRICH_DATALAKE_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Long Term Token used to access Orange Cyberdefense Datalake API. |
| CONNECTOR_NAME | `string` |  | string | `"Orange Cyberdefense CTI Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "URL", "Email-Addr", "Autonomous-System", "X509-Certificate", "Cryptocurrency-Wallet", "StixFile", "Phone-Number"]` | OpenCTI observable types for which to enable the enrichment. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| OCD_ENRICH_DATALAKE_ENV | `string` |  | string | `"prod"` | Datalake environment to use: `prod` or `preprod`. |
| OCD_ENRICH_IGNORE_UNSCORED_INDICATORS | `boolean` |  | boolean | `true` | If `true`, Datalake indicators that do not have any score will be ignored. |
| OCD_ENRICH_IGNORE_WHITELISTED_INDICATORS | `boolean` |  | boolean | `true` | If `true`, Datalake indicators that are whitelisted will be ignored. |
| OCD_ENRICH_FALLBACK_SCORE | `integer` |  | integer | `0` | If `OCD_ENRICH_IGNORE_UNSCORED_INDICATORS` is set to `false`, this value will be used as a default for Datalake indicators without any score. |
| OCD_ENRICH_ADD_TAGS_AS_LABELS | `boolean` |  | boolean | `true` | Whether to add Datalake tags as labels to the enriched observable. |
| OCD_ENRICH_ADD_SCORES_AS_LABELS | `boolean` |  | boolean | `true` | Whether to add Datalake threat scores as labels to the enriched observable. |
| OCD_ENRICH_ADD_TLP | `boolean` |  | boolean | `true` | Whether to add a TLP marking to the enriched observable (overwrite existing). |
| OCD_ENRICH_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean | `true` | Whether to transform Datalake 'Threat Actor' objects into 'Intrusion Set' objects. |
| OCD_ENRICH_ADD_SCORE | `boolean` |  | boolean | `true` | Whether to add score to the enriched observable (overwrite existing). |
| OCD_ENRICH_ADD_EXTREF | `boolean` |  | boolean | `true` | Whether to add external references to the enriched observable. |
| OCD_ENRICH_ADD_SUMMARY | `boolean` |  | boolean | `true` | Whether to add a threat summary as a note to the enriched observable. |
| OCD_ENRICH_ADD_RELATED | `boolean` |  | boolean | `true` | Whether to import objects from the Threat Library related to this observable, such as indicators, malwares, etc. |
| OCD_ENRICH_ADD_SIGHTINGS | `boolean` |  | boolean | `true` | Whether to import positive sightings from Datalake. |
| OCD_ENRICH_ADD_CREATEDBY | `boolean` |  | boolean | `true` | Whether to add a reference to 'Orange Cyberdefense' organization as author of OpenCTI objects. |
| OCD_ENRICH_CURATE_LABELS | `boolean` |  | boolean | `true` | Adapt Datalake CTI tags as STIX labels. |
| OCD_ENRICH_MAX_TLP | `string` |  | string | `"TLP:GREEN"` | Only perform enrichment for observables with this TLP level or less restrictive. |
