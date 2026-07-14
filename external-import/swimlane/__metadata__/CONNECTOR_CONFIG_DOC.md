# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| SWIMLANE_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the Swimlane instance (e.g. https://swimlane.example.com). |
| SWIMLANE_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Swimlane API token (Personal Access Token) used for authentication. |
| SWIMLANE_APPLICATION_ID | `string` | ✅ | string |  | ID of the Swimlane application whose records are imported. |
| CONNECTOR_NAME | `string` |  | string | `"Swimlane"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT15M"` | The period of time to await between two runs of the connector. |
| SWIMLANE_MAX_RECORDS | `integer` |  | `1 <= x ` | `100` | Maximum number of records to fetch per run. |
| SWIMLANE_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to the imported case-incidents. |
| SWIMLANE_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the Swimlane instance. |
