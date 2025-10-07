# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The token of the user who represents the connector in the OpenCTI platform. |
| SPLUNK_SOAR_URL | `string` | ✅ | string |  | The Splunk SOAR platform URL. |
| CONNECTOR_NAME | `string` |  | string | `"Splunk SOAR Push"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"splunk-soar-push"` | The scope or type of data the connector is processing. |
| CONNECTOR_TYPE | `string` |  | string | `"STREAM"` | Should always be set to STREAM for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Determines the verbosity of the logs. |
| CONNECTOR_CONFIDENCE_LEVEL | `integer` |  | `0 <= x <= 100` | `100` | The default confidence level for created entities (0-100). |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"ChangeMe"` | The ID of the live stream to listen to. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Listen to delete events in the stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `false` | Do not auto-resolve dependencies. |
| SPLUNK_SOAR_API_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | API token for Splunk SOAR authentication (preferred). |
| SPLUNK_SOAR_USERNAME | `string` |  | string | `null` | Username for Splunk SOAR (if not using token). |
| SPLUNK_SOAR_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Password for Splunk SOAR (if not using token). |
| SPLUNK_SOAR_VERIFY_SSL | `boolean` |  | boolean | `true` | Verify SSL certificates when connecting to SOAR. |
| SPLUNK_SOAR_PROXY_URL | `string` |  | string | `null` | Proxy URL if needed for SOAR connection. |
| SPLUNK_SOAR_DELETE_ON_REMOVAL | `boolean` |  | boolean | `false` | Close SOAR entities when removed from stream. |
| SPLUNK_SOAR_DEFAULT_SEVERITY | `string` |  | string | `"medium"` | Default severity for SOAR entities. |
| SPLUNK_SOAR_DEFAULT_STATUS | `string` |  | string | `"new"` | Default status for SOAR entities. |
| SPLUNK_SOAR_MAX_ARTIFACTS_PER_CONTAINER | `integer` |  | integer | `1000` | Maximum artifacts per container. |
| SPLUNK_SOAR_BATCH_SIZE | `integer` |  | integer | `100` | Batch size for bulk operations. |
| PROXY_HTTP | `string` |  | string | `null` | HTTP proxy URL. |
| PROXY_HTTPS | `string` |  | string | `null` | HTTPS proxy URL. |
| PROXY_NO_PROXY | `string` |  | string | `null` | Comma-separated list of hosts that should not use proxy. |
