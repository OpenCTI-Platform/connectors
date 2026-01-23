# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
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
| CONNECTOR_SCOPE | `array` |  | string |  | `["dummy"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| DUMMY_ENRICHMENT_NEW_MAX_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | Max TLP level of the entities to enrich. |
| TOTO_MAMAMA | `integer` |  | integer | ⛔️ | `null` | Use TOTO_MOMOMO instead. |
| TOTO_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| TATA_IMAGE | `string` |  | string | ⛔️ |  | Use TOTO_IMAGE instead. |
| TATA_MOVIE | `string` |  | string | ⛔️ |  | Use TOTO_MOVIE instead. |
| TATA_MAMAMA | `integer` |  | integer | ⛔️ | `null` | Use TOTO_MOMOMO instead. |
| TATA_MOMOMO | `string` |  | string | ⛔️ |  | Use TOTO_MOMOMO instead. |
| TATA_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| DUMMY_ENRICHMENT_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use DUMMY_ENRICHMENT_NEW_API_BASE_URL instead. |
| DUMMY_ENRICHMENT_API_KEY | `string` |  | string | ⛔️ |  | Use DUMMY_ENRICHMENT_NEW_API_KEY instead. |
| DUMMY_ENRICHMENT_MAX_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | ⛔️ | `"amber+strict"` | Use DUMMY_ENRICHMENT_NEW_MAX_TLP_LEVEL instead. |
| DUMMY_ENRICHMENT_TABLE | `string` |  | string | ⛔️ |  | Use DUMMY_ENRICHMENT_NEW_TABLE instead. |
| CHRISTMAS_OLD_OS | `string` |  | string | ⛔️ |  | Use CHRISTMAS_OS instead. |
| CHRISTMAS_OLD_DAY | `string` |  | string | ⛔️ |  | Use CHRISTMAS_DAY instead. |
