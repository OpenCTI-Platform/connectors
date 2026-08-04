# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| IBM_XTI_TAXII_SERVER_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the IBM X-Force PTI TAXII Server. |
| IBM_XTI_TAXII_USER | `string` | ✅ | string |  | Your TAXII Server username. |
| IBM_XTI_TAXII_PASS | `string` | ✅ | string |  | Your TAXII Server password. |
| CONNECTOR_NAME | `string` |  | string | `"IBMXTIConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector. |
| IBM_XTI_TAXII_COLLECTIONS | `string` |  | string | `""` | Comma-separated list of collection IDs to ingest. |
| IBM_XTI_CREATE_OBSERVABLES | `boolean` |  | boolean | `false` | Create observables from indicators. |
| IBM_XTI_DEBUG | `boolean` |  | boolean | `false` | Enable debug mode (developers only) |
