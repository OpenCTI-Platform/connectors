# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| VECTRA_AI_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the Vectra AI Platform (e.g. https://vectra.example.com). |
| VECTRA_AI_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token used to authenticate against the Vectra AI API. |
| CONNECTOR_NAME | `string` |  | string | `"Vectra AI Intel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["vectra-ai"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| VECTRA_AI_API_VERSION | `string` |  | string | `"v2.5"` | Version of the Vectra API used to reach the threat feed endpoints. |
| VECTRA_AI_FEED_NAME | `string` |  | string | `"OpenCTI"` | Name of the Vectra threat feed managed by this connector. It is created automatically if it does not exist yet. |
| VECTRA_AI_FEED_CATEGORY | `string` |  | `cnc` `malware` `recon` `exfil` `lateral` | `"cnc"` | Detection category assigned to the Vectra threat feed. |
| VECTRA_AI_FEED_CERTAINTY | `string` |  | `Low` `Medium` `High` | `"High"` | Certainty assigned to indicators matched against the threat feed. |
| VECTRA_AI_FEED_DURATION | `integer` |  | `1 <= x ` | `14` | Number of days indicators remain active in the Vectra threat feed before they expire. |
| VECTRA_AI_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the Vectra AI API. |
