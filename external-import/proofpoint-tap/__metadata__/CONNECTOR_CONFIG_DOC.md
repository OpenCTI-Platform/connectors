# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| PROOFPOINT_TAP_API_PRINCIPAL_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Proofpoint API principal key for authentication. |
| PROOFPOINT_TAP_API_SECRET_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Proofpoint API secret key for authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"ProofPointTAP"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["report"]` | The type of data the connector is importing, i.e. the type of Stix Objects (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT12H"` | The period of time to await between two runs of the connector. |
| PROOFPOINT_TAP_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://tap-api-v2.proofpoint.com/"` | Proofpoint API base URL. |
| PROOFPOINT_TAP_API_TIMEOUT | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT30S"` | Timeout duration for API requests. |
| PROOFPOINT_TAP_API_BACKOFF | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT5S"` | Backoff duration for API requests. |
| PROOFPOINT_TAP_API_RETRIES | `integer` |  | integer |  | `3` | Number of retries for API requests. |
| PROOFPOINT_TAP_MARKING_DEFINITION | `string` |  | `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | Default TLP level of the imported entities. |
| PROOFPOINT_TAP_EXPORT_CAMPAIGNS | `boolean` |  | boolean |  | `true` | Whether to export Proofpoint campaigns and import them into OpenCTI. |
| PROOFPOINT_TAP_EXPORT_EVENTS | `boolean` |  | boolean |  | `false` | Whether to export Proofpoint events and import them into OpenCTI. |
| PROOFPOINT_TAP_EVENTS_TYPE | `string` |  | `all` `issues` `messages_blocked` `messages_delivered` `clicks_blocked` `clicks_permitted` |  | `"issues"` | The type of events to export (`PROOFPOINT_TAP_EXPORT_EVENTS` must be enabled). |
| TAP_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"https://tap-api-v2.proofpoint.com/"` | Use PROOFPOINT_TAP_API_BASE_URL instead. (removal scheduled for 2026-08-27) |
| TAP_API_PRINCIPAL_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use PROOFPOINT_TAP_API_PRINCIPAL_KEY instead. (removal scheduled for 2026-08-27) |
| TAP_API_SECRET_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use PROOFPOINT_TAP_API_SECRET_KEY instead. (removal scheduled for 2026-08-27) |
| TAP_API_TIMEOUT | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"PT30S"` | Use PROOFPOINT_TAP_API_TIMEOUT instead. (removal scheduled for 2026-08-27) |
| TAP_API_BACKOFF | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `"PT5S"` | Use PROOFPOINT_TAP_API_BACKOFF instead. (removal scheduled for 2026-08-27) |
| TAP_API_RETRIES | `integer` |  | integer | ⛔️ | `3` | Use PROOFPOINT_TAP_API_RETRIES instead. (removal scheduled for 2026-08-27) |
| TAP_MARKING_DEFINITION | `string` |  | `white` `green` `amber` `amber+strict` `red` | ⛔️ | `"amber+strict"` | Use PROOFPOINT_TAP_MARKING_DEFINITION instead. (removal scheduled for 2026-08-27) |
| TAP_EXPORT_CAMPAIGNS | `boolean` |  | boolean | ⛔️ | `true` | Use PROOFPOINT_TAP_EXPORT_CAMPAIGNS instead. (removal scheduled for 2026-08-27) |
| TAP_EXPORT_EVENTS | `boolean` |  | boolean | ⛔️ | `false` | Use PROOFPOINT_TAP_EXPORT_EVENTS instead. (removal scheduled for 2026-08-27) |
| TAP_EVENTS_TYPE | `string` |  | `all` `issues` `messages_blocked` `messages_delivered` `clicks_blocked` `clicks_permitted` | ⛔️ | `"issues"` | Use PROOFPOINT_TAP_EVENTS_TYPE instead. (removal scheduled for 2026-08-27) |
