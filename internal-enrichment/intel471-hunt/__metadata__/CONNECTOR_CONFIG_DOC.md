# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| HUNTER_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Intel 471 Hunter API key, sent as `Authorization: API-Key <key>`. Obtained separately from Verity471/Titan credentials. |
| CONNECTOR_NAME | `string` |  | string | `"Intel 471 Hunter"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Report", "Indicator", "Note", "Intrusion-Set", "Threat-Actor", "Threat-Actor-Group", "Threat-Actor-Individual", "Campaign", "Attack-Pattern", "Vulnerability", "Malware", "Tool", "Sector", "Country", "Region"]` | Entity types the connector can be triggered on, plus every type it emits (Report, Indicator, Note) — OpenCTI drops unlisted types. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| HUNTER_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.hunter.cyborgsecurity.io/"` | Base URL of the Intel 471 Hunter API. |
| HUNTER_UI_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://hunter.cyborgsecurity.io/"` | Base URL of the Hunter UI, used to build external references back to each hunt. Leave empty to omit those links. |
| HUNTER_INDEXES | `string` |  | string | `"cyborg_usecases"` | Hunter index to query. |
| HUNTER_REQUEST_TIMEOUT_SECONDS | `integer` |  | `0 < x ` | `30` | HTTP timeout, in seconds, for calls to the Hunter API. |
| HUNTER_MAX_RESULTS_PER_QUERY | `integer` |  | `0 < x ` | `100` | Maximum number of hunt packages retrieved per query. |
| HUNTER_CACHE_PATH | `string` |  | string | `"/opt/opencti-connector-intel471-hunt/cache/cache.json"` | Path of the local `(hunt_uuid, last_updated)` cache. Keep this on a dedicated directory: mounting a volume over the connector's working directory shadows its code. |
| HUNTER_CACHE_TTL_HOURS | `integer` |  | `0 < x ` | `24` | Lifetime, in hours, of a cache entry. |
| HUNTER_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | The maximal TLP of the entity being enriched. |
