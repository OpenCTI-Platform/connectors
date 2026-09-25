# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| VISIONHEIGHT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | VisionHeight API key used to authenticate requests (sent as the x-api-key header). |
| CONNECTOR_NAME | `string` |  | string | `"VisionHeight"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "Domain-Name"]` | Comma-separated list of OpenCTI entity types this connector enriches. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| VISIONHEIGHT_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.visionheight.com"` | VisionHeight API base URL. Override for white-label or staging endpoints. |
| VISIONHEIGHT_MAX_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Maximum TLP level of observables this connector will enrich. Observables marked above this level cause the enrichment to abort with an error logged. |
