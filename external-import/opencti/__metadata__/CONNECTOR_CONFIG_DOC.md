# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"OpenCTI Datasets"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["marking-definition", "identity", "location"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONFIG_SECTORS_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json"` | URL to sectors dataset (set to `false` or leave empty to disable). |
| CONFIG_GEOGRAPHY_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json"` | URL to geography dataset (set to `false` or leave empty to disable). |
| CONFIG_COMPANIES_FILE_URL | `string` |  | string | `"https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json"` | URL to companies dataset (set to `false` or leave empty to disable). |
| CONFIG_REMOVE_CREATOR | `boolean` |  | boolean | `false` | Remove creator identity from imported objects. |
| CONFIG_INTERVAL | `integer` |  | integer | `7` | Interval in days between connector runs. |
