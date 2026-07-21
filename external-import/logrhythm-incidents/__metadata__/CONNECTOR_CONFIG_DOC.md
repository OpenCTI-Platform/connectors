# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| LOGRHYTHM_INCIDENTS_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the LogRhythm API gateway (e.g. https://logrhythm.example.com:8501). |
| LOGRHYTHM_INCIDENTS_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | LogRhythm API token (Bearer) used for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"LogRhythm Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["logrhythm"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT15M"` | The period of time to await between two runs of the connector. |
| LOGRHYTHM_INCIDENTS_MAX_CASES | `integer` |  | `1 <= x ` | `200` | Maximum number of LogRhythm cases to fetch per run. |
| LOGRHYTHM_INCIDENTS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to the imported incidents. |
| LOGRHYTHM_INCIDENTS_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the LogRhythm API gateway. |
