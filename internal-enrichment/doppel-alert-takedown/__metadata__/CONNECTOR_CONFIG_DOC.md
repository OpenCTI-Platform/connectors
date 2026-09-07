# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Doppel Alert and Takedown"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Url", "Domain-Name"]` | The scope of the connector (types of observables to enrich). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| DOPPEL_ALERT_TAKEDOWN_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.doppel.com/"` | Doppel API base URL. A trailing /v1 or /v2 is accepted and normalized to the selected api_version. |
| DOPPEL_ALERT_TAKEDOWN_API_VERSION | `string` |  | `v1` `v2` | `"v1"` | Doppel API version. Choose exactly one authentication mode: V1 API keys or V2 OAuth client credentials. |
| DOPPEL_ALERT_TAKEDOWN_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | V1 API key sent as the x-api-key header. Required for V1 and must be unset for V2. |
| DOPPEL_ALERT_TAKEDOWN_USER_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | V1 user API key sent as the x-user-api-key header. Required for V1 and must be unset for V2. |
| DOPPEL_ALERT_TAKEDOWN_CLIENT_ID | `string` |  | string | `null` | OAuth client ID required for V2 and must be unset for V1. |
| DOPPEL_ALERT_TAKEDOWN_CLIENT_SECRET | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | OAuth client secret required for V2 and must be unset for V1. |
| DOPPEL_ALERT_TAKEDOWN_TOKEN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional V2 OAuth token endpoint. Defaults to /oauth/token on the API base URL and must be unset for V1. |
| DOPPEL_ALERT_TAKEDOWN_TOKEN_AUDIENCE | `string` |  | Length: `string >= 1` | `"doppel-external"` | OAuth audience used only for the V2 client-credentials exchange. |
| DOPPEL_ALERT_TAKEDOWN_TAGS | `array` |  | string | `[]` | List of tags to attach to the alerts created in Doppel. |
| DOPPEL_ALERT_TAKEDOWN_TAKEDOWN_COMMENT | `string` |  | string | `"Confirmed by OpenCTI — requesting takedown."` | Comment sent to Doppel when requesting a takedown. |
| DOPPEL_ALERT_TAKEDOWN_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:RED"` | Max TLP level of entities to enrich. |
