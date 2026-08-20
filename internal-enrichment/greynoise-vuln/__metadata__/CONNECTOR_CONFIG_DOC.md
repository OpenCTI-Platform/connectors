# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GREYNOISE_VULN_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The GreyNoise API key. |
| CONNECTOR_NAME | `string` |  | string | `"GreyNoise Vulnerability Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["vulnerability"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| GREYNOISE_VULN_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | The maximal TLP of the vulnerability being enriched. |
| GREYNOISE_VULN_NAME | `string` |  | string | `"GreyNoise Internet Scanner"` | The name of the GreyNoise entity (used as the author identity in STIX). |
| GREYNOISE_VULN_DESCRIPTION | `string` |  | string | `"GreyNoise collects and analyzes opportunistic scan and attack activity for devices connected directly to the Internet."` | The description of the GreyNoise entity. |
