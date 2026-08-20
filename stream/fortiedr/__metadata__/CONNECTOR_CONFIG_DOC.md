# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
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
| FORTIEDR_ORGANIZATION | `string` |  | string | `""` | FortiEDR organization name (required on multi-tenant consoles, used as the user prefix). |
| FORTIEDR_IP_SET_NAME | `string` |  | string | `"OpenCTI"` | Name of the FortiEDR IP Set managed by this connector. It is created automatically if it does not exist yet. |
| FORTIEDR_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the FortiEDR Central Manager. |
