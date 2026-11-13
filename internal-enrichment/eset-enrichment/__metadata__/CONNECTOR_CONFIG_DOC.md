# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| ESET_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | ESET Threat Intelligence API key. |
| ESET_API_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | ESET Threat Intelligence API secret. |
| CONNECTOR_NAME | `string` |  | string |  | `"ESET ETI Report Enrichment Connector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["report"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"red"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| ESET_API_HOST | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://eti.eset.com/"` | ESET Threat Intelligence API base URL. |
| CONNECTOR_TEMPLATE_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
