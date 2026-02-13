# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_ID | `string` | ✅ | string |  | A UUID v4 to identify the connector in OpenCTI. |
| CONNECTOR_NAME | `string` | ✅ | string | `"MokN"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` | ✅ | string | `["mokn"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` | ✅ | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Determines the verbosity of the logs. |
| CONNECTOR_DURATION_PERIOD | `string` |  | string | `"PT1H"` | The period of time to await between two runs of the connector. |
| MOKN_CONSOLE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the MokN console. |
| MOKN_API_KEY | `string` | ✅ | string |  | Your MokN API key. |
| MOKN_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking level for imported data. |
| MOKN_FIRST_RUN_DAYS_BACK | `integer` |  | `0 < x` | `30` | Number of days to retrieve on first execution. |

