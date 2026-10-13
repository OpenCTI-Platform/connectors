# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| TEMPLATE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate against the external API. |
| CONNECTOR_NAME | `string` |  | string | `"TemplateConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector e.g., the type of entities the connector imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour) |
| TEMPLATE_IMPORT_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The start date (ISO 8601 format) for importing data. Can be either absolute e.g., a given date like '2023-01-01T00:00:00Z' or relative e.g., a given period of time like 'P30D' (meaning '30 days ago'). Used as the initial checkpoint on connector first run; subsequent runs resume from connector state. |
| TEMPLATE_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `true` | Enable/disable the import of vulnerabilities. |
| TEMPLATE_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Enable/disable the import of reports. |
| TEMPLATE_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP (Traffic Light Protocol) marking applied to every object this connector creates in OpenCTI. |
