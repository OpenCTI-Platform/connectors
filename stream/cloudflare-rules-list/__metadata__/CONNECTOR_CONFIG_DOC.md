# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| CLOUDFLARE_ACCOUNT_ID | `string` | ✅ | string |  | Cloudflare account ID that owns the Rules List. |
| CLOUDFLARE_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Cloudflare API token with the 'Account > Account Filter Lists > Edit' permission. |
| CLOUDFLARE_LIST_ID | `string` | ✅ | string |  | ID of the existing Cloudflare Rules List (IP kind) to sync into. |
| CONNECTOR_NAME | `string` |  | string | `"Cloudflare Rules List"` | The name of the connector as shown in OpenCTI. |
| CONNECTOR_SCOPE | `array` |  | string | `["cloudflare"]` | Connector scope (comma-separated). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean | `true` | Whether to replay historical stream events on first start. It only controls the stream replay: the connector always runs a full sync of the existing IPv4 indicators and observables at startup, whatever this value. Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | ISO 8601 date up to which historical stream events are replayed when recover is enabled. Leave empty to replay all existing events. Ignored when recover is disabled, and it does not limit the startup full sync. Only applied on the connector's first run (no existing state). |
| CLOUDFLARE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.cloudflare.com/client/v4"` | Base URL of the Cloudflare API. Override only for testing against a mock server or a Cloudflare-compatible gateway. |
| CLOUDFLARE_SYNC_INTERVAL | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Minimum interval between snapshot uploads to Cloudflare. Accepts ISO-8601 duration like 'PT30M', 'PT1H', 'PT1H30M', etc. |
