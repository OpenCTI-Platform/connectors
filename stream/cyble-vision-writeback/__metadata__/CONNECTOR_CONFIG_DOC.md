# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CYBLE_VISION_WRITEBACK_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Cyble Vision API bearer token with permission to update alerts. |
| CONNECTOR_NAME | `string` |  | string | `"Cyble Vision Writeback"` | Display name in OpenCTI. |
| CONNECTOR_SCOPE | `array` |  | string | `["Incident"]` | Entity types this connector reacts to. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"live"` | ID of the live stream to listen to. 'live' is the global stream; a stream filtered on Incidents labelled 'cyble' reduces traffic. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `false` | Listen to delete events. Disabled by default, since write-back never deletes anything in Vision. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean | `false` | Replay stream history on first start. Disabled by default so only new analyst updates are written back. |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | ISO 8601 date up to which historical events are replayed when recover is enabled. Leave empty to replay all existing data. Ignored when recover is disabled. Only applied on the connector's first run (no existing state). |
| CYBLE_VISION_WRITEBACK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://bifrost.cyble.ai"` | Cyble Vision API base URL. |
| CYBLE_VISION_WRITEBACK_IGNORED_USER_NAMES | `array` |  | string | `["Cyble Vision"]` | OpenCTI user names whose changes are not written back. Set it to the user the Cyble Vision import connector runs as, so imported values are not echoed back to Vision. |
