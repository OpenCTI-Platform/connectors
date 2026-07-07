# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CORELIGHT_INVESTIGATOR_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Corelight Investigator API base URL (region specific, e.g. https://eu.api.investigator.corelight.com). |
| CORELIGHT_INVESTIGATOR_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Corelight Investigator API key (sent as an Authorization bearer header). |
| CONNECTOR_NAME | `string` |  | string | `"Corelight Investigator"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["corelight-investigator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CORELIGHT_INVESTIGATOR_ALERTS_PATH | `string` |  | string | `"/api/v1/alerts"` | Path of the Investigator Detections and Alerts API endpoint. |
| CORELIGHT_INVESTIGATOR_IMPORT_WINDOW_DAYS | `integer` |  | `0 < x ` | `7` | Number of days to look back on the first run. |
| CORELIGHT_INVESTIGATOR_MAX_ALERTS | `integer` |  | `0 < x ` | `1000` | Maximum number of alerts to request per run. |
| CORELIGHT_INVESTIGATOR_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | Default TLP marking applied to the imported entities. |
| CORELIGHT_INVESTIGATOR_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the API server TLS certificate. |
