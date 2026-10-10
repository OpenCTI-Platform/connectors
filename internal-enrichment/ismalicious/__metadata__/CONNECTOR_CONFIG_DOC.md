# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ISMALICIOUS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The isMalicious API key. |
| CONNECTOR_NAME | `string` |  | string | `"isMalicious"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| ISMALICIOUS_API_URL | `string` |  | string | `"https://api.ismalicious.com"` | The base URL of the isMalicious API. |
| ISMALICIOUS_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP level of the observables to enrich. |
| ISMALICIOUS_ENRICH_IPV4 | `boolean` |  | boolean | `true` | Whether to enrich IPv4 addresses. |
| ISMALICIOUS_ENRICH_IPV6 | `boolean` |  | boolean | `true` | Whether to enrich IPv6 addresses. |
| ISMALICIOUS_ENRICH_DOMAIN | `boolean` |  | boolean | `true` | Whether to enrich domain names. |
| ISMALICIOUS_MIN_SCORE | `integer` |  | `0 <= x <= 100` | `0` | Minimum risk score (0-100) required to report a finding. |
