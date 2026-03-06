# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| SHADOWTRACKR_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"ShadowTrackr"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Indicator"]` | The scope of the connector, e.g. 'IPv4-Addr,IPv6-Addr,Indicator'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| SHADOWTRACKR_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://shadowtrackr.com/api/v3"` | Base URL of the ShadowTrackr API. |
| SHADOWTRACKR_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Max TLP level of the entities to enrich. |
| SHADOWTRACKR_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean | `false` | Replace the score with a lower score based on the ShadowTrackr false positive estimate. |
| SHADOWTRACKR_REPLACE_VALID_TO_DATE | `boolean` |  | boolean | `false` | Set the valid to date to tomorrow for CDNs, Clouds and VPNs. |
