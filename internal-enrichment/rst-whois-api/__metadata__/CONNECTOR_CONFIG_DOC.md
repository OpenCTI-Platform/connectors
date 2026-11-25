# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| RST_WHOIS_API_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The RST Cloud API key. |
| CONNECTOR_NAME | `string` |  | string |  | `"RST WHOIS API"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Domain-Name", "Url", "indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| RST_WHOIS_API_BASE_URL | `string` |  | string |  | `"https://api.rstcloud.net/v1"` | The base URL of the RST Cloud API. |
| RST_WHOIS_API_TIMEOUT | `integer` |  | integer |  | `10` | The timeout of the RST Cloud API requests, in seconds. |
| RST_WHOIS_API_WHOIS_OUTPUT_OBJECT | `string` |  | string |  | `"note"` | Where to store the WHOIS data: 'note' to create a Note attached to the entity, 'description' to update the description of the entity. |
| RST_WHOIS_API_UPDATE_OUTPUT_ACTION | `string` |  | string |  | `"overwrite"` | How to store the WHOIS data: 'overwrite' to replace the previous data, 'append' to add the new data to the previous one. |
| RST_WHOIS_API_OUTPUT_FORMAT | `string` |  | string |  | `"standard"` | The WHOIS data format: 'standard' for the basic WHOIS fields, 'extended' for additional WHOIS fields. |
| RST_WHOIS_API_OUTPUT_INCLUDE_RAW | `boolean` |  | boolean |  | `false` | Whether to include the raw WHOIS response in the output. |
| RST_WHOIS_API_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
