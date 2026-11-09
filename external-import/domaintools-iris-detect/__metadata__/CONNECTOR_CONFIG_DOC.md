# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| DOMAINTOOLS_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API base URL. |
| DOMAINTOOLS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"DomainToolsIrisDetectConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["stix2"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| DOMAINTOOLS_MONITOR_ID | `string` |  | string | `null` | Monitor ID from the monitors response – only used when requesting domains for specific monitors. |
| DOMAINTOOLS_STORE_IRIS_DATA | `boolean` |  | boolean | `false` | Store DomainTools Iris data as note object. |
| DOMAINTOOLS_PREVIEW | `boolean` |  | boolean | `false` | Use during API implementation and testing. Including with value = 1 will limit results to 2 but not be limited by hourly restrictions. |
| DOMAINTOOLS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
