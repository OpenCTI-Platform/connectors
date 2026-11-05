# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ImportExternalReference"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["External-Reference"]` | The scope (MIME types) handled by the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_PDF | `boolean` |  | boolean | `true` | Import external references as PDF files. |
| IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_MD | `boolean` |  | boolean | `true` | Import external references as Markdown files. |
| IMPORT_EXTERNAL_REFERENCE_IMPORT_PDF_AS_MD | `boolean` |  | boolean | `true` | If import_as_md is true, try to convert the PDF to Markdown. |
| IMPORT_EXTERNAL_REFERENCE_TIMESTAMP_FILES | `boolean` |  | boolean | `false` | If true, timestamp imported files to prevent overwriting versions. |
| IMPORT_EXTERNAL_REFERENCE_CACHE_SIZE | `integer` |  | `0 < x ` | `32` | Size of the LRU URL cache to prevent fetching the same object repeatedly. |
| IMPORT_EXTERNAL_REFERENCE_CACHE_TTL | `integer` |  | `0 < x ` | `3600` | Time-to-live (in seconds) for cache entries. |
| IMPORT_EXTERNAL_REFERENCE_BROWSER_WORKER_COUNT | `integer` |  | `0 < x ` | `4` | Number of browser worker threads to use. |
| IMPORT_EXTERNAL_REFERENCE_MAX_DOWNLOAD_SIZE | `integer` |  | `0 < x ` | `52428800` | Maximum download size in bytes. (default: 50MB) |
