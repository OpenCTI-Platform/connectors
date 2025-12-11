# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| SENTINELONE_INTEL_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of your SentinelOne management console |
| SENTINELONE_INTEL_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key for your SentinelOne management console |
| CONNECTOR_NAME | `string` |  | string | `"SentinelOne Intel Stream Connector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `"sentinelone"` | The scope of the connector, e.g. 'sentinelone'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"live"` | The ID of the live stream to connect to. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| SENTINELONE_INTEL_ACCOUNT_ID | `integer` |  | integer | `null` | The Account ID for your SentinelOne management console |
| SENTINELONE_INTEL_SITE_ID | `integer` |  | integer | `null` | The Site ID for your SentinelOne management console |
| SENTINELONE_INTEL_GROUP_ID | `integer` |  | integer | `null` | The Group ID for your SentinelOne management console |
