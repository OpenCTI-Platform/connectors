# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| RADAR_BASE_FEED_URL | `string` | ✅ | string |  |  | SOCRadar Feed API base URL. |
| RADAR_SOCRADAR_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API key to connect to SOCRadar. |
| RADAR_FEED_LISTS | `array` | ✅ | object |  |  | The SOCRadar feed lists to fetch. |
| RADAR_FEED_LISTS[].name | `string` | ✅ | string |  |  | The name of SOCRadar feed list to fetch. |
| RADAR_FEED_LISTS[].id | `string` | ✅ | string |  |  | The ID of SOCRadar feed list to fetch. |
| CONNECTOR_NAME | `string` |  | string |  | `"SOCRadar"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["socradar"]` | The scope of the connector, e.g. 'socradar'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT10M"` | The period of time to await between two runs of the connector. |
| RADAR_RUN_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| RADAR_COLLECTIONS_UUID | `object` |  | object | ⛔️ | `null` | Use RADAR_FEED_LISTS instead. |
