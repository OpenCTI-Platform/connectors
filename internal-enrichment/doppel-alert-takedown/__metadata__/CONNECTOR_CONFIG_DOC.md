# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default                                              | Description |
| -------- | ---- | -------- | --------------- |------------------------------------------------------| ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |                                                      | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |                                                      | The API token to connect to OpenCTI. |
| DOPPEL_API_KEY | `string` | ✅ | string |                                                      | Doppel API key, sent as the `x-api-key` header. |
| DOPPEL_USER_API_KEY | `string` | ✅ | string |                                                      | Doppel user API key, sent as the `x-user-api-key` header. |
| CONNECTOR_NAME | `string` |  | string | `"Doppel Alert and Takedown"`                             | The name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"Url,Domain-Name"`                                  | The scope of the connector (types of observables to enrich). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"`                                            | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"`                              |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false`                                              | Whether the connector should run automatically when an entity is created or updated. |
| DOPPEL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.doppel.com/"`                          | Doppel API base URL. |
| DOPPEL_TAGS | `array` |  | string |                                                      | List of tags to attach to the alerts created in Doppel. |
| DOPPEL_TAKEDOWN_COMMENT | `string` |  | string | `"Confirmed by OpenCTI \u2014 requesting takedown."` | Comment sent to Doppel when requesting a takedown. |
| DOPPEL_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` `` | `""`                                                 | Max TLP level of entities to enrich (empty = no limit). |
