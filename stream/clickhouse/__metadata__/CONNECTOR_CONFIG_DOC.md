# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| CLICKHOUSE_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the ClickHouse HTTP interface (e.g. http://clickhouse:8123). |
| CONNECTOR_NAME | `string` |  | string | `"ClickHouse"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["clickhouse"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CLICKHOUSE_USERNAME | `string` |  | string | `"default"` | ClickHouse user name. |
| CLICKHOUSE_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `""` | ClickHouse user password. |
| CLICKHOUSE_DATABASE | `string` |  | string | `"default"` | ClickHouse database to write to. |
| CLICKHOUSE_TABLE | `string` |  | string | `"opencti_stream"` | ClickHouse table that receives the OpenCTI stream events. |
| CLICKHOUSE_CREATE_TABLE | `boolean` |  | boolean | `true` | Whether to create the destination database and table automatically on startup. |
| CLICKHOUSE_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the ClickHouse HTTP interface. |
