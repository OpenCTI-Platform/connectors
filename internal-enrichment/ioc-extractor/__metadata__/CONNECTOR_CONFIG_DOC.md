# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"IOC Extractor"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Report"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| IOC_EXTRACTOR_EXTRACT_HASHES | `boolean` |  | boolean | `true` | Extract file hashes (MD5, SHA-1, SHA-256). |
| IOC_EXTRACTOR_EXTRACT_IPV4 | `boolean` |  | boolean | `true` | Extract IPv4 addresses. |
| IOC_EXTRACTOR_EXTRACT_IPV6 | `boolean` |  | boolean | `true` | Extract IPv6 addresses. |
| IOC_EXTRACTOR_EXTRACT_DOMAINS | `boolean` |  | boolean | `true` | Extract domain names. |
| IOC_EXTRACTOR_EXTRACT_URLS | `boolean` |  | boolean | `true` | Extract URLs. |
| IOC_EXTRACTOR_SKIP_PRIVATE_IPS | `boolean` |  | boolean | `true` | Skip private/reserved IP addresses (RFC 1918, loopback, etc.). |
| IOC_EXTRACTOR_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | The maximal TLP of the observable being enriched. |
