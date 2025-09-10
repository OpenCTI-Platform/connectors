# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string |  | `"Abuse.ch | ThreatFox"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string |  | `"ThreatFox"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string |  | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | Determines the verbosity of the logs. |
| THREATFOX_CSV_URL | `string` |  | string |  | `"https://threatfox.abuse.ch/export/csv/recent/"` | The Threat Fox URL |
| THREATFOX_IMPORT_OFFLINE | `boolean` |  | boolean |  | `true` | Create records for indicators that are offline. |
| THREATFOX_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | Create indicators in addition to observables. |
| THREATFOX_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer |  | `50` | The default x_opencti_score to use. |
| THREATFOX_X_OPENCTI_SCORE_IP | `integer` |  | integer |  | `null` | Set the x_opencti_score for IP observables. |
| THREATFOX_X_OPENCTI_SCORE_DOMAIN | `integer` |  | integer |  | `null` | Set the x_opencti_score for Domain observables. |
| THREATFOX_X_OPENCTI_SCORE_URL | `integer` |  | integer |  | `null` | Set the x_opencti_score for URL observables. |
| THREATFOX_X_OPENCTI_SCORE_HASH | `integer` |  | integer |  | `null` | Set the x_opencti_score for Hash observables. |
| THREATFOX_IOC_TO_IMPORT | `string` |  | string |  | `"all_types"` | List of IOC types to retrieve, available parameters: all_types, ip:port, domain, url, md5_hash, sha1_hash, sha256_hash |
| THREATFOX_INTERVAL | `integer` |  | integer | ⛔️ | `3` | [DEPRECATED] Interval in days between two scheduled runs of the connector. |
