# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ImportDocumentAI"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["application/pdf", "text/plain", "text/html", "text/markdown"]` | The scope (supported MIME types) of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_IMPORT_FILE` | `"INTERNAL_IMPORT_FILE"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_XTM_ONE_INTENT | `string` |  | string | `"cti.stix_harvester"` | XTM One intent for agent-based extraction. |
| IMPORT_DOCUMENT_AI_INCLUDE_RELATIONSHIPS | `boolean` |  | boolean | `true` | Whether to include relationships extracted from the document. |
| IMPORT_DOCUMENT_AI_CREATE_INDICATOR | `boolean` |  | boolean | `false` | Whether to flag extracted observables for indicator creation. |
| IMPORT_DOCUMENT_AI_API_BASE_URL | `string` |  | string | `null` | Base URL of the Import Document AI web service (legacy direct mode). |
| IMPORT_DOCUMENT_AI_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | PEM licence/certificate key used to authenticate against the web service (legacy direct mode). |
