# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| SHADOWSERVER_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Shadowserver API key. |
| SHADOWSERVER_API_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Shadowserver API secret. |
| CONNECTOR_NAME | `string` |  | string |  | `"Shadowserver"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["stix2"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | The period of time to await between two runs of the connector. |
| SHADOWSERVER_MARKING | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:WHITE"` | TLP marking: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`. |
| SHADOWSERVER_CREATE_INCIDENT | `boolean` |  | boolean |  | `false` | Create Case Incident from reports. |
| SHADOWSERVER_INCIDENT_SEVERITY | `string` |  | string |  | `"low"` | Default incident severity. |
| SHADOWSERVER_INCIDENT_PRIORITY | `string` |  | string |  | `"P4"` | Default incident priority. |
| SHADOWSERVER_REPORT_TYPES | `array` |  | string |  | `[]` | List of report types to retrieve. If empty, all report types will be retrieved. |
| SHADOWSERVER_INITIAL_LOOKBACK | `integer` |  | integer |  | `30` | Number of days to look back for reports during the first run. |
| SHADOWSERVER_LOOKBACK | `integer` |  | integer |  | `3` | Number of days to look back for reports during subsequent runs. |
| SHADOWSERVER_MAX_THREADS | `integer` |  | `1 <= x <= 32` |  | `8` | Maximum number of threads used to download and transform reports in parallel. |
| CONNECTOR_RUN_EVERY | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
