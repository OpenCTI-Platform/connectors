# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"CATALYST"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["catalyst"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector (ISO-8601 duration format). |
| CATALYST_BASE_URL | `string` |  | string | `"https://prod.blindspot.prodaft.com/api"` | The base URL of the CATALYST API. |
| CATALYST_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | The CATALYST API key. If not provided, the public endpoint is used. |
| CATALYST_TLP_LEVEL | `string` |  | string | `"white"` | Default TLP marking applied to the imported data. |
| CATALYST_TLP_FILTER | `string` |  | string | `"ALL"` | Comma-separated list of TLP levels to fetch (options: CLEAR, GREEN, AMBER, RED, ALL). |
| CATALYST_CATEGORY_FILTER | `string` |  | string | `"ALL"` | Comma-separated list of categories to fetch (options: DISCOVERY, ATTRIBUTION, RESEARCH, FLASH_ALERT, ALL). |
| CATALYST_SYNC_DAYS_BACK | `integer` |  | integer | `730` | Number of days to go back when no last run is present in the connector state. |
| CATALYST_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create observables from the fetched data. |
| CATALYST_CREATE_INDICATORS | `boolean` |  | boolean | `false` | Whether to create indicators from the fetched data. |
