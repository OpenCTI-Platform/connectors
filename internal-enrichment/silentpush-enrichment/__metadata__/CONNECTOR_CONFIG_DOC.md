# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| SILENTPUSH_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"Silent Push - Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "URL"]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| SILENTPUSH_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://app.silentpush.com/api/v2/"` | External API base URL. |
| SILENTPUSH_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Max TLP level of the entities to enrich. |
| SILENTPUSH_VERIFY_CERT | `boolean` |  | boolean | `true` | Whether to verify SSL certificates when connecting to the API. |
