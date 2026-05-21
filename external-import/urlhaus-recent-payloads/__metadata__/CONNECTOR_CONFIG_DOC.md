# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| URLHAUS_RECENT_PAYLOADS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key for the URLhaus API. |
| CONNECTOR_NAME | `string` |  | string | `"UrlhausRecentPayloads"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector. |
| URLHAUS_RECENT_PAYLOADS_API_URL | `string` |  | string | `"https://urlhaus-api.abuse.ch/v1/"` | The URL of the URLhaus API. |
| URLHAUS_RECENT_PAYLOADS_INCLUDE_FILETYPES | `array` |  | string | `[]` | Only download files if file type matches. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_INCLUDE_SIGNATURES | `array` |  | string | `[]` | Only download files if match these Yara rules. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_SKIP_UNKNOWN_FILETYPES | `boolean` |  | boolean | `true` | Skip files with an unknown file type. |
| URLHAUS_RECENT_PAYLOADS_SKIP_NULL_SIGNATURE | `boolean` |  | boolean | `true` | Skip files that didn't match known Yara rules. |
| URLHAUS_RECENT_PAYLOADS_LABELS | `array` |  | string | `["urlhaus"]` | Labels to apply to uploaded Artifacts. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_LABELS_COLOR | `string` |  | string | `"#54483b"` | Color for labels specified above. |
| URLHAUS_RECENT_PAYLOADS_SIGNATURE_LABEL_COLOR | `string` |  | string | `"#0059f7"` | Color for Yara rule match label. |
| URLHAUS_RECENT_PAYLOADS_FILETYPE_LABEL_COLOR | `string` |  | string | `"#54483b"` | Color to use for filetype label. |
