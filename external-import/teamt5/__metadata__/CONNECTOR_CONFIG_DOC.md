# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Team T5 External Import Connector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| TEAMT5_API_BASE_URL | `string` |  | string | `"https://api.threatvision.org/"` | Base URL of the TeamT5 ThreatVision API. |
| TEAMT5_CLIENT_ID | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | OAuth 2.0 client ID. Requires `client_secret` to also be set. |
| TEAMT5_CLIENT_SECRET | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | OAuth 2.0 client secret. Requires `client_id` to also be set. |
| TEAMT5_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Deprecated. Static API key for authentication to TeamT5's ThreatVision Platform. Prefer `client_id` + `client_secret`. |
| TEAMT5_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
| TEAMT5_FIRST_RUN_RETRIEVAL_TIMESTAMP | `integer` |  | integer | `0` | Unix timestamp indicating the earliest point in time from which intel should be retrieved from the TeamT5 API. Used only on the connector's first run to import previously published data. Defaults to 0 (i.e. the full TeamT5 catalogue) so existing deployments that never set this variable continue to start. |
