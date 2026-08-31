# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |  |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |  |
| CONNECTOR_NAME | `string` |  | string | `"Malanta Attribution"` | The name of the connector. |  |
| CONNECTOR_SCOPE | `array` |  | string | `["indicator"]` | Entity types processed by the connector. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `false` | Whether to listen for delete events on the live stream. Disabled by default: this connector only adds attribution and does not revoke it. |  |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |  |
| MALANTA_ATTRIBUTION_LABEL_PREFIX | `string` |  | string | `"apt:"` | Label namespace treated as threat-actor attribution. Labels not starting with this prefix are ignored. | ```apt:``` |
| MALANTA_ATTRIBUTION_ACTOR_SEPARATORS | `array` |  | string | `[","]` | Characters splitting several actors inside a single label. Malanta occasionally emits comma-joined tokens such as 'apt:APT17,APT5'. | ```,``` |
| MALANTA_ATTRIBUTION_AUTHOR_NAME | `string` |  | string | `"Malanta.ai"` | Organization credited with the derived Intrusion Sets and relationships. Keep this identical to the feed's author so derived attribution merges with the ingested data. | ```Malanta.ai``` |
| MALANTA_ATTRIBUTION_SOURCE_AUTHOR | `string` |  | string | `"Malanta.ai"` | Only process indicators authored by this organization. Prevents attributing another feed's `apt:` labels to Malanta when several sources are ingested into the same platform. Set to an empty string to process indicators from every source. | ```Malanta.ai``` |
| MALANTA_ATTRIBUTION_AUTHOR_DESCRIPTION | `string` |  | string | `null` | Optional description for the author organization. |  |
| MALANTA_ATTRIBUTION_CREATE_INTRUSION_SETS | `boolean` |  | boolean | `true` | Create the Intrusion Set when it does not exist. Disable to emit only relationships towards Intrusion Sets managed elsewhere. |  |
| MALANTA_ATTRIBUTION_MIN_CONFIDENCE | `integer` |  | `0 <= x <= 100` | `0` | Skip indicators whose confidence is below this threshold. 0 processes everything. |  |
