# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| SUMOLOGIC_INTEL_API_BASE_URL | `string` | ✅ | string |  | The base URL of the Sumo Logic API. |
| SUMOLOGIC_INTEL_ACCESS_ID | `string` | ✅ | string |  | The Sumo Logic access ID used to authenticate against the API. |
| SUMOLOGIC_INTEL_ACCESS_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The Sumo Logic access key used to authenticate against the API. |
| CONNECTOR_NAME | `string` |  | string | `"Sumo Logic Intel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["sumologic"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
