# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| FORTISIEM_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the FortiSIEM Supervisor (e.g. https://fortisiem.example.com). |
| FORTISIEM_USERNAME | `string` | ✅ | string |  | FortiSIEM REST API user name. |
| FORTISIEM_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | FortiSIEM REST API user password. |
| FORTISIEM_WATCHLIST_ID | `integer` | ✅ | integer |  | Numeric ID of the FortiSIEM Watch List that receives the IOCs. |
| CONNECTOR_NAME | `string` |  | string | `"FortiSIEM"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["fortisiem"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| FORTISIEM_ORGANIZATION | `string` |  | string | `"super"` | FortiSIEM organization used to scope the REST API user (e.g. 'super'). |
| FORTISIEM_ENTRY_AGE_OUT | `string` |  | string | `"30d"` | Age-out applied to Watch List entries so they expire automatically (e.g. '30d'). |
| FORTISIEM_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the FortiSIEM Supervisor. |
