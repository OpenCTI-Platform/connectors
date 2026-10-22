# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| SHODAN_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Shodan API Key |
| CONNECTOR_NAME | `string` |  | string |  | `"Shodan"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["ipv4-addr", "indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| SHODAN_DEFAULT_SCORE | `integer` |  | integer |  | `50` | Default_score allows you to add a default score for an indicator and its observable |
| SHODAN_IMPORT_SEARCH_RESULTS | `boolean` |  | boolean |  | `true` | Returns the results of the search against the enriched indicator (Search the SHODAN database). |
| SHODAN_CREATE_NOTE | `boolean` |  | boolean |  | `true` | Adds Shodan results to a note, otherwise it is saved in the description. |
| SHODAN_USE_ISP_NAME_FOR_ASN | `boolean` |  | boolean |  | `false` | Use the ISP name for ASN name rather than AS+Number. |
| SHODAN_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
