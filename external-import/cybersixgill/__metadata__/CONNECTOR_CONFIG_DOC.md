# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CYBERSIXGILL_CLIENT_ID | `string` | ✅ | string |  | Cybersixgill API Client ID. |
| CYBERSIXGILL_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Cybersixgill API Client Secret. |
| CONNECTOR_NAME | `string` |  | string | `"Cybersixgill Darkfeed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["cybersixgill"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `false` | Whether to update data already ingested into the platform. |
| CYBERSIXGILL_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create observables from indicators. |
| CYBERSIXGILL_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Create STIX indicators. |
| CYBERSIXGILL_ENABLE_RELATIONSHIPS | `boolean` |  | boolean | `true` | Create relationships between SDOs. |
| CYBERSIXGILL_FETCH_SIZE | `integer` |  | integer | `2000` | Number of indicators to fetch per run. |
| CYBERSIXGILL_INTERVAL_SEC | `integer` |  | integer | `300` | Import interval in seconds. |
