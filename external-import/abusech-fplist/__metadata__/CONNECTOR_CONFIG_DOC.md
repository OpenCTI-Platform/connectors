# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ABUSECH_FPLIST_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your abuse.ch Auth-Key from the Authentication Portal. |
| CONNECTOR_NAME | `string` |  | string | `"AbusechFplist"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | How often to run (ISO-8601 duration). |
| ABUSECH_FPLIST_API_BASE_URL | `string` |  | string | `"https://hunting-api.abuse.ch/api/v1/"` | Hunting API endpoint. |
| ABUSECH_FPLIST_DRY_RUN | `boolean` |  | boolean | `false` | If true, log which Indicators would be deleted without actually deleting them. |
