# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| CROWDSTRIKE_CLIENT_ID | `string` | ✅ | string |  | Crowdstrike client ID used to connect to the API. |
| CROWDSTRIKE_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Crowdstrike client secret used to connect to the API. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdstrikeEndpointSecurity"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crowdstrike-endpoint-security"]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CROWDSTRIKE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.crowdstrike.com"` | Crowdstrike base url. |
| CROWDSTRIKE_PERMANENT_DELETE | `boolean` |  | boolean | `false` | Select whether or not to permanently delete data in Crowdstrike when data is deleted in OpenCTI. If set to `True`, `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` must be set to `True`. |
| CROWDSTRIKE_FALCON_FOR_MOBILE_ACTIVE | `boolean` |  | boolean | `false` | Enable Android and iOS platform support. |
| METRICS_ENABLE | `boolean` |  | boolean | `false` | Whether or not Prometheus metrics should be enabled. |
| METRICS_PORT | `integer` |  | integer | `9113` | Port to use for metrics endpoint. |
| METRICS_ADDR | `string` |  | string | `"0.0.0.0"` | Bind IP address to use for metrics endpoint. |
