# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| CLOUDFLARE_ACCOUNT_ID | `string` | ✅ | string |  | Cloudflare account ID that owns the Rules List. |
| CLOUDFLARE_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Cloudflare API token with the 'Account > Account Filter Lists > Edit' permission. |
| CLOUDFLARE_LIST_ID | `string` | ✅ | string |  | ID of the existing Cloudflare Rules List (IP kind) to sync into. |
| CONNECTOR_NAME | `string` |  | string | `"Cloudflare Rules List"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["cloudflare"]` | The scope of the stream connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_SYNC_INTERVAL | `string` |  | string | `"1h"` | Minimum interval between snapshot uploads to Cloudflare. Accepts a duration like '30m', '1h', '1h30m', or a bare number of seconds. |
| CLOUDFLARE_API_BASE_URL | `string` |  | string | `"https://api.cloudflare.com/client/v4"` | Base URL of the Cloudflare API. Override only for testing against a mock server or a Cloudflare-compatible gateway. |
