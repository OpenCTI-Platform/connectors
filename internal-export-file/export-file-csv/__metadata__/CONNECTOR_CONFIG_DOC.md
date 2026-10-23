# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ExportFileCsv"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["text/csv"]` | The scope of the connector, i.e. the MIME type of the exported files. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_EXPORT_FILE` | `"INTERNAL_EXPORT_FILE"` |  |
| EXPORT_FILE_CSV_DELIMITER | `string` |  | string | `";"` | The delimiter character used to separate the values in the exported CSV files. |
| EXPORT_FILE_CSV_ADD_BOM | `boolean` |  | boolean | `false` | Prepend a UTF-8 BOM (byte order mark) to exported CSV files. Required for Microsoft Excel to correctly auto-detect UTF-8 encoding Without it, Excel falls back to the system's local codepageand non-ASCII text (Arabic, Cyrillic, CJK, etc.) is rendered as garbled characters. Disabled by default. |
