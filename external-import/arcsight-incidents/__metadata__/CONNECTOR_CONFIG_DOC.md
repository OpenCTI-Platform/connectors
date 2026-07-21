# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ARCSIGHT_INCIDENTS_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the ArcSight ESM Manager (e.g. https://arcsight.example.com:8443). |
| ARCSIGHT_INCIDENTS_USERNAME | `string` | ✅ | string |  | ArcSight ESM user name. |
| ARCSIGHT_INCIDENTS_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ArcSight ESM user password. |
| CONNECTOR_NAME | `string` |  | string | `"ArcSight Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT15M"` | The period of time to await between two runs of the connector. |
| ARCSIGHT_INCIDENTS_MAX_CASES | `integer` |  | `1 <= x ` | `200` | Maximum number of ESM cases to fetch per run. |
| ARCSIGHT_INCIDENTS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to the imported incidents. |
| ARCSIGHT_INCIDENTS_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the ArcSight ESM Manager. |
