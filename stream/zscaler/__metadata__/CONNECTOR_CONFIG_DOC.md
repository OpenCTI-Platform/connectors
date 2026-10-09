# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  |  | The ID of the live stream to connect to. |
| ZSCALER_CLIENT_ID | `string` | ✅ | string |  |  | Client ID of the ZIdentity API client used to authenticate to Zscaler OneAPI. |
| ZSCALER_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Client secret of the ZIdentity API client. |
| ZSCALER_VANITY_DOMAIN | `string` | ✅ | string |  |  | ZIdentity vanity domain of the organization, i.e. the `<vanity_domain>` part of `https://<vanity_domain>.zslogin.net`. |
| CONNECTOR_NAME | `string` |  | string |  | `"Zscaler"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["domain-name"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` |  | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean |  | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean |  | `true` | Whether to ignore dependencies when processing events from the live stream. |
| CONNECTOR_LIVE_STREAM_START_TIMESTAMP | `integer` |  | integer |  | `null` | Stream position to start from, as epoch milliseconds (13 digits). Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER | `boolean` |  | boolean |  | `true` | Whether to replay historical events from the database on first start (recover/backfill). Enabled by default: on its first run the connector replays all existing data (up to 'live_stream_recover_iso_date' if set) before switching to live events. Set to false to only process new events from now on. Only applied on the connector's first run (no existing state). |
| CONNECTOR_LIVE_STREAM_RECOVER_ISO_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | ISO 8601 date up to which historical events are replayed when recover is enabled. Leave empty to replay all existing data. Ignored when recover is disabled. Only applied on the connector's first run (no existing state). |
| ZSCALER_CLOUD | `string` |  | string |  | `null` | Zscaler cloud to target (for example `beta`). Leave empty to use the production cloud (`api.zsapi.net`). |
| ZSCALER_BLACKLIST_NAME | `string` |  | string |  | `"BLACK_LIST_DYNDNS"` | ID of the Zscaler URL category used as blacklist (for example `CUSTOM_01`), not its display name. |
| ZSCALER_SSL_VERIFY | `boolean` |  | boolean |  | `true` | Whether to verify SSL certificates when connecting to the Zscaler API. |
| ZSCALER_USERNAME | `string` |  | string | ⛔️ | `null` | Zscaler account username (legacy API, no longer used). |
| ZSCALER_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Zscaler account password (legacy API, no longer used). |
| ZSCALER_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Zscaler API key (legacy API, no longer used). |
