# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| VECTRA_AI_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the Vectra AI Platform (e.g. https://vectra.example.com). |
| VECTRA_AI_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token used to authenticate against the Vectra AI API. |
| CONNECTOR_NAME | `string` |  | string | `"Vectra AI Intel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["vectra-ai"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean | `true` | Whether to replay historical events from the database on first start (recover/backfill). Enabled by default: on its first run the connector replays all existing data (up to 'live_stream_recover_iso_date' if set) before switching to live events. Set to false to only process new events from now on. Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | ISO 8601 date up to which historical events are replayed when recover is enabled. Leave empty to replay all existing data. Ignored when recover is disabled. Only applied on the connector's first run (no existing state). |
| VECTRA_AI_API_VERSION | `string` |  | string | `"v2.5"` | Version of the Vectra API used to reach the threat feed endpoints. |
| VECTRA_AI_FEED_NAME | `string` |  | string | `"OpenCTI"` | Name of the Vectra threat feed managed by this connector. It is created automatically if it does not exist yet. |
| VECTRA_AI_FEED_CATEGORY | `string` |  | `cnc` `malware` `recon` `exfil` `lateral` | `"cnc"` | Detection category assigned to the Vectra threat feed. |
| VECTRA_AI_FEED_CERTAINTY | `string` |  | `Low` `Medium` `High` | `"High"` | Certainty assigned to indicators matched against the threat feed. |
| VECTRA_AI_FEED_DURATION | `integer` |  | `1 <= x ` | `14` | Number of days indicators remain active in the Vectra threat feed before they expire. |
| VECTRA_AI_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the Vectra AI API. |
