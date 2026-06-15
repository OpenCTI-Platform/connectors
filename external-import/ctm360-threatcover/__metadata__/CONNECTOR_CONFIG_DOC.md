# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |
| CTM360_THREATCOVER_API_ROOT_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CTM360 ThreatCover TAXII 2.1 API root URL (tenant specific). |
| CTM360_THREATCOVER_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CTM360 ThreatCover API token (sent as the TAXII Authorization header). |
| CTM360_THREATCOVER_COLLECTION_ID | `string` | ✅ | string |  | TAXII collection id to poll (the ThreatCover 'Observables' collection). |
| CONNECTOR_NAME | `string` |  | string | `"CTM360 ThreatCover"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CTM360_THREATCOVER_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | Default TLP level applied to the imported entities. |
| CTM360_THREATCOVER_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TAXII server TLS certificate. |
