# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ImportDocument"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["application/pdf", "text/plain", "text/csv", "text/html", "text/markdown", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `string` |  | `INTERNAL_IMPORT_FILE` `INTERNAL_ANALYSIS` | `"INTERNAL_IMPORT_FILE"` | The type of the connector. `INTERNAL_ANALYSIS` runs the connector in content mapping mode. Ignored when `IMPORT_DOCUMENT_MODE` is set, which catalog deployments must use since they cannot set this value. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_VALIDATE_BEFORE_IMPORT | `boolean` |  | boolean | `true` | Validate any bundle before import. |
| CONNECTOR_ONLY_CONTEXTUAL | `boolean` |  | boolean | `false` | If `true`, only extract data when an entity context is provided. |
| IMPORT_DOCUMENT_CREATE_INDICATOR | `boolean` |  | boolean | `false` | If true, creates an Indicator for each extracted observable. |
| IMPORT_DOCUMENT_MODE | `string` |  | `import` `analysis` | `null` | `import` registers the connector as a file import connector, which parses uploaded files into entities. `analysis` registers it as an analysis connector, used by 'Ask new mapping' in the Content tab of containers. Deploy one instance per mode to use both. When not set, the mode follows `CONNECTOR_TYPE`. |
