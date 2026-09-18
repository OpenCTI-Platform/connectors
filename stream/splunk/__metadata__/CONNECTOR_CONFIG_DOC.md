# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| SPLUNK_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the Splunk instance (e.g. https://splunk:8089). |
| SPLUNK_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Token used to authenticate against the Splunk API. |
| SPLUNK_OWNER | `string` | ✅ | string |  | Splunk owner namespace used to access the KV Store collection. |
| SPLUNK_APP | `string` | ✅ | string |  | Splunk app namespace hosting the KV Store collection. |
| SPLUNK_KV_STORE_NAME | `string` | ✅ | string |  | Name of the Splunk KV Store collection to feed. |
| CONNECTOR_NAME | `string` |  | string | `"Splunk"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean | `true` | Whether to replay historical events from the database on first start (recover/backfill). Enabled by default: on its first run the connector replays all existing data (up to 'live_stream_recover_iso_date' if set) before switching to live events. Set to false to only process new events from now on. Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | ISO 8601 date up to which historical events are replayed when recover is enabled. Leave empty to replay all existing data. Ignored when recover is disabled. Only applied on the connector's first run (no existing state). |
| CONNECTOR_CONSUMER_COUNT | `integer` |  | integer | `10` | Number of consumer/worker threads used to push data to Splunk. |
| SPLUNK_AUTH_TYPE | `string` |  | string | `"Bearer"` | Authorization scheme used with the Splunk token. |
| SPLUNK_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the Splunk instance. |
| SPLUNK_IGNORE_TYPES | `array` |  | string | `[]` | Comma-separated list of entity types to ignore. |
| METRICS_ENABLE | `boolean` |  | boolean | `false` | Whether to expose Prometheus metrics. |
| METRICS_PORT | `integer` |  | integer | `9113` | Port on which metrics should be exposed. |
| METRICS_ADDR | `string` |  | string | `"0.0.0.0"` | IP address on which metrics should be exposed. |
