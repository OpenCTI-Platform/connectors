# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  |  | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_DURATION_PERIOD | `integer` | ✅ | integer |  |  | The period (in seconds) between two runs of the connector. |
| TOTO_IMAGE | `string` | ✅ | string |  |  | image |
| TOTO_MOVIE | `string` | ✅ | string |  |  | movie |
| TOTO_MOMOMO | `string` | ✅ | string |  |  | momomo |
| DUMMY_ENRICHMENT_NEW_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | External API base URL. |
| DUMMY_ENRICHMENT_NEW_API_KEY | `string` | ✅ | string |  |  | API key for authentication. |
| DUMMY_ENRICHMENT_NEW_TABLE | `string` | ✅ | string |  |  | Table |
| CHRISTMAS_OS | `string` | ✅ | string |  |  | os |
| CHRISTMAS_DAY | `string` | ✅ | string |  |  | day |
| CONNECTOR_NAME | `string` |  | string |  | `"DummyEnrichmentConnector"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| DUMMY_ENRICHMENT_NEW_MAX_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | Max TLP level of the entities to enrich. |
| TOTO_USELESS | `None` |  | None | ⛔️ | `null` |  |
| TOTO_MAMAMA | `None` |  | None | ⛔️ | `null` |  |
| TOTO_INTERVAL | `None` |  | None | ⛔️ | `null` |  |
