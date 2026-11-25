# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| RST_IOC_LOOKUP_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The RST Cloud API key. |
| CONNECTOR_NAME | `string` |  | string |  | `"RST IoC Lookup"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["IPv4-Addr", "Domain-Name", "Url", "StixFile", "indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| RST_IOC_LOOKUP_BASE_URL | `string` |  | string |  | `"https://api.rstcloud.net/v1"` | The RST Cloud API base URL. |
| RST_IOC_LOOKUP_UPDATE_CONFIDENCE | `boolean` |  | boolean |  | `true` | Whether to set the indicator confidence to the RST Cloud source score. |
| RST_IOC_LOOKUP_UPDATE_SCORE | `boolean` |  | boolean |  | `true` | Whether to update the score of the observable or indicator. |
| RST_IOC_LOOKUP_UPDATE_VALID_FROM | `boolean` |  | boolean |  | `true` | Whether to move the indicator `valid_from` to the last seen date (and shift `valid_until` accordingly). |
| RST_IOC_LOOKUP_SCORE_TYPE | `string` |  | string |  | `"total"` | The RST Cloud score to use: `last` (score on the last seen day), `first` (score on the first seen day) or `total` (decayed score). |
| RST_IOC_LOOKUP_UPDATE_DESCRIPTION_ACTION | `string` |  | string |  | `"overwrite"` | How to merge the RST Cloud description into the existing one: `overwrite`, `append` or `prepend`. |
| RST_IOC_LOOKUP_DETECTION_FLAG_THRESHOLD | `integer` |  | integer |  | `45` | Score from which the indicator detection flag is set to true (below, it is set to false). `0` leaves the detection flag unchanged. |
| RST_IOC_LOOKUP_LABEL_FORMAT | `string` |  | string |  | `"short"` | Label format: `short` (suffixes such as `_group` or `_ransomware` removed) or `long` (labels kept as returned by RST Cloud). |
| RST_IOC_LOOKUP_TIMEOUT | `integer` |  | integer |  | `10` | The RST Cloud API request timeout, in seconds. |
| RST_IOC_LOOKUP_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
