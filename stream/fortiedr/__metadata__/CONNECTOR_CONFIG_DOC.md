# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| FORTIEDR_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the FortiEDR Central Manager (e.g. https://console.fortiedr.example.com). |
| FORTIEDR_USERNAME | `string` | ✅ | string |  | FortiEDR REST API user name. |
| FORTIEDR_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | FortiEDR REST API user password. |
| CONNECTOR_NAME | `string` |  | string | `"FortiEDR"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["fortiedr"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean | `true` | Whether to replay historical events from the database on first start (recover/backfill). Enabled by default: on its first run the connector replays all existing data (up to 'live_stream_recover_iso_date' if set) before switching to live events. Set to false to only process new events from now on. Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | ISO 8601 date up to which historical events are replayed when recover is enabled. Leave empty to replay all existing data. Ignored when recover is disabled. Only applied on the connector's first run (no existing state). |
| FORTIEDR_ORGANIZATION | `string` |  | string | `""` | FortiEDR organization name (required on multi-tenant consoles, used as the user prefix). |
| FORTIEDR_IP_SET_NAME | `string` |  | string | `"OpenCTI"` | Name of the FortiEDR IP Set managed by this connector. It is created automatically if it does not exist yet. |
| FORTIEDR_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the FortiEDR Central Manager. |
