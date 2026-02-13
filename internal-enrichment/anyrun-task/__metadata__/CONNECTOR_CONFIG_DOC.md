# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ANYRUN_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ANY.RUN API token for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"ANY.RUN task"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact", "Url"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| ANYRUN_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP level for the connector. |
| ANYRUN_URL | `string` |  | string | `"https://api.any.run"` | Base URL for the ANY.RUN API. |
| ANYRUN_TASK_TIMER | `integer` |  | integer | `60` | Sandbox execution time in seconds. |
| ANYRUN_OS | `string` |  | string | `"windows"` | Operating system for sandbox environment. |
| ANYRUN_OS_BITNESS | `string` |  | `32` `64` | `"64"` | Operating system bitness: `32` or `64`. |
| ANYRUN_OS_VERSION | `string` |  | `7` `8.1` `10` `11` | `"10"` | Windows version: `7`, `8.1`, `10`, or `11`. |
| ANYRUN_OS_LOCALE | `string` |  | string | `"en-US"` | Operating system language locale. |
| ANYRUN_OS_BROWSER | `string` |  | `Google Chrome` `Mozilla Firefox` `Opera` `Internet Explorer` `Microsoft Edge` | `"Google Chrome"` | Browser for URL analysis: `Google Chrome`, `Mozilla Firefox`, `Opera`, `Internet Explorer`, `Microsoft Edge`. |
| ANYRUN_PRIVACY | `string` |  | `public` `bylink` `owner` `team` | `"bylink"` | Task privacy: `public`, `bylink`, `owner`, `team`. |
| ANYRUN_AUTOMATED_INTERACTIVITY | `boolean` |  | boolean | `false` | Enable ML-based automated interactivity during analysis. |
| ANYRUN_IOC | `boolean` |  | boolean | `true` | Import IOCs (domains, URLs, IPs) extracted during analysis. |
| ANYRUN_MITRE | `boolean` |  | boolean | `false` | Create relationships to MITRE ATT&CK techniques. |
| ANYRUN_PROCESSES | `boolean` |  | boolean | `false` | Import malicious process observables. |
