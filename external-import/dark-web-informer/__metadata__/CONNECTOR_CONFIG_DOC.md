# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |  |
| DARK_WEB_INFORMER_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The Dark Web Informer API key, sent as the X-API-Key header. | ```your-dwi-api-key``` |
| CONNECTOR_NAME | `string` |  | string | `"Dark Web Informer"` | The name of the connector. | ```Dark Web Informer``` |
| CONNECTOR_SCOPE | `array` |  | string | `["dark-web-informer"]` | The scope of the connector. | ```dark-web-informer``` |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | ISO-8601 duration between two runs of the connector. | ```PT6H``` |
| DARK_WEB_INFORMER_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.darkwebinformer.com"` | Base URL of the Dark Web Informer API. | ```https://api.darkwebinformer.com``` |
| DARK_WEB_INFORMER_SOURCES | `array` |  | string | `["feed", "ransomware", "iocs"]` | Which prebuilt STIX bundles to ingest: feed, ransomware, iocs (or all). | ```feed,ransomware,iocs``` |
| DARK_WEB_INFORMER_USE_PREVIEW_ENDPOINT | `boolean` |  | boolean | `false` | Use the smaller on-demand /api/stix.json preview instead of the full bulk bundles (useful for testing). | ```False``` |
| DARK_WEB_INFORMER_PREVIEW_LIMIT | `integer` |  | integer | `5000` | Object limit when use_preview_endpoint is true (max 5000). | ```5000``` |
