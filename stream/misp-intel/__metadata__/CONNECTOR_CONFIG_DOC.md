# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| MISP_URL | `string` | ✅ | string |  | MISP instance URL (e.g., https://misp.example.com). |
| MISP_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | MISP API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"MISP Intel"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["misp"]` | The scope or type of data the connector is processing. |
| CONNECTOR_TYPE | `string` |  | string | `"STREAM"` | Should always be set to STREAM for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Determines the verbosity of the logs. |
| CONNECTOR_CONFIDENCE_LEVEL | `integer` |  | `0 <= x <= 100` | `80` | The default confidence level for created entities (0-100). |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"live"` | The ID of the live stream to listen to. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Listen to delete events in the stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `false` | Do not auto-resolve dependencies. |
| CONNECTOR_CONTAINER_TYPES | `array` |  | string | `["report", "grouping", "case-incident", "case-rfi", "case-rft"]` | List of container types to process. |
| MISP_SSL_VERIFY | `boolean` |  | boolean | `true` | Verify SSL certificates when connecting to MISP. |
| MISP_OWNER_ORG | `string` |  | string | `null` | Organization that will own the events in MISP (leave empty to use MISP default). |
| MISP_DISTRIBUTION_LEVEL | `integer` |  | `0 <= x <= 3` | `1` | Distribution level for MISP events: 0: Your organisation only, 1: This community only, 2: Connected communities, 3: All communities |
| MISP_THREAT_LEVEL | `integer` |  | `1 <= x <= 4` | `2` | Threat level for MISP events: 1: High, 2: Medium, 3: Low, 4: Undefined |
| MISP_PUBLISH_ON_CREATE | `boolean` |  | boolean | `false` | Automatically publish events when created. |
| MISP_PUBLISH_ON_UPDATE | `boolean` |  | boolean | `false` | Automatically publish events when updated. |
| MISP_TAG_OPENCTI | `boolean` |  | boolean | `true` | Add OpenCTI-specific tags to MISP events. |
| MISP_TAG_PREFIX | `string` |  | string | `"opencti:"` | Prefix for OpenCTI tags in MISP. |
| MISP_HARD_DELETE | `boolean` |  | boolean | `true` | Perform hard deletion of MISP events (permanent deletion without blocklisting). If False, deleted events are added to the blocklist to prevent re-importation. If True, events are permanently deleted and can be re-imported later. |
| PROXY_HTTP | `string` |  | string | `null` | HTTP proxy URL (e.g., http://proxy:8080). |
| PROXY_HTTPS | `string` |  | string | `null` | HTTPS proxy URL (e.g., http://proxy:8080). |
| PROXY_NO_PROXY | `string` |  | string | `"localhost,127.0.0.1"` | Comma-separated list of hosts to bypass proxy. |
