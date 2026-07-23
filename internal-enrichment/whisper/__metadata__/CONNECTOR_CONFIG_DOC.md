# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |  |
| WHISPER_API_URL | `string` | ✅ | string |  | Base URL of the Whisper graph API, e.g. 'https://graph.whisper.security'. The connector POSTs Cypher to '<api_url>/api/query'. | ```https://graph.whisper.security``` |
| WHISPER_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Whisper API key, sent in the X-API-Key header. Never logged. | ```whisper-0123456789abcdef0123456789abcdef``` |
| CONNECTOR_NAME | `string` |  | string | `"Whisper"` | Connector display name. |  |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Autonomous-System"]` | Observable types this connector enriches. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |  |
| WHISPER_MAX_TLP | `string` |  | string | `"TLP:AMBER+STRICT"` | Maximum TLP marking the connector will enrich. Observables marked above this level are skipped. Set 'TLP:RED' to disable the gate. | ```TLP:AMBER+STRICT```, ```TLP:RED``` |
