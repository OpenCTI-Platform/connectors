# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| PROOFPOINT_ET_INTELLIGENCE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key used for authentication to ProofPoint ET Intelligence. |
| CONNECTOR_NAME | `string` |  | string | `"ProofPoint ET Intelligence"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "Domain-Name", "StixFile"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | Enable/disable auto-enrichment of observables. |
| PROOFPOINT_ET_INTELLIGENCE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.emergingthreats.net/v1/"` | The base URL of the ProofPoint ET Intelligence API. |
| PROOFPOINT_ET_INTELLIGENCE_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER+STRICT"` | Maximum TLP level the connector is authorized to enrich. Available values: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED. |
| PROOFPOINT_ET_INTELLIGENCE_IMPORT_LAST_SEEN_TIME_WINDOW | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | The time window for importing 'last_seen' data, specified in ISO 8601 duration format. |
