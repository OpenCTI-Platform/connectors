# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"DisarmFramework"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["marking-definition", "identity", "attack-pattern", "course-of-action", "intrusion-set", "campaign", "malware", "tool", "report", "narrative", "event", "channel"]` | The scope of the connector. Only these object types will be imported on OpenCTI. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P7D"` | The period of time to await between two runs of the connector. |
| DISARM_FRAMEWORK_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_files/DISARM_STIX/DISARM.json"` | URL of the DISARM STIX bundle. |
