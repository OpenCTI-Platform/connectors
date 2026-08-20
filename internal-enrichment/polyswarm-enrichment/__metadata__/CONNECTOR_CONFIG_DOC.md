# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| POLYSWARM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | PolySwarm API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"PolySwarm Hash Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile", "Artifact"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| POLYSWARM_COMMUNITY | `string` |  | string | `"default"` | PolySwarm community ('default' or 'private' for dual-community). |
| POLYSWARM_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` `` | `""` | Max TLP level of entities to enrich (empty = no limit). |
| POLYSWARM_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean | `true` | If false, keep higher existing score instead of overwriting. |
| POLYSWARM_MAX_POLLING_TIME | `integer` |  | integer | `120` | Maximum wait time for scan results in seconds. |
| POLYSWARM_IOC_ENABLED | `boolean` |  | boolean | `true` | Enable network IOC extraction from PolySwarm IOC API. |
| POLYSWARM_IOC_MAX_COUNT | `integer` |  | integer | `20` | Max network IOC observables per enrichment (global cap). |
| POLYSWARM_IOC_SCORE | `integer` |  | integer | `20` | x_opencti_score for network IOC observables. |
| POLYSWARM_IOC_TYPES | `array` |  | string | `["ip", "domain", "url"]` | Which IOC types to create (comma-separated: ip,domain,url). |
| POLYSWARM_POLYKG_API_URL | `string` |  | string | `""` | polykg REST API URL for malware profile enrichment (empty = disabled). |
