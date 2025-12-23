# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Malpedia"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `"malpedia"` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| MALPEDIA_AUTH_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | API authentication key |
| MALPEDIA_IMPORT_INTRUSION_SETS | `boolean` |  | boolean | `true` | Choose if you want to import Intrusion-Sets from Malpedia |
| MALPEDIA_IMPORT_YARA | `boolean` |  | boolean | `true` | Choose if you want to import Yara rules from Malpedia |
| MALPEDIA_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Choose if you want to create Indicators Sample (File) from Malpedia |
| MALPEDIA_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Choose if you want to create Observables Sample (File) from Malpedia |
| MALPEDIA_DEFAULT_MARKING | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:RED` | `null` | The default TLP marking to apply to entities created by the connector. If not defined, the default when an API key is provided is `TLP:AMBER`, otherwise `TLP:WHITE`. |
