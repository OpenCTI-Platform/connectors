# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ASSETNOTE_IMPORT_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API base URL. |
| ASSETNOTE_IMPORT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"AssetnoteImportConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Assetnote"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| ASSETNOTE_IMPORT_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
| ASSETNOTE_IMPORT_UNRESOLVED_STATUS_NAME | `string` |  | string | `null` | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote UNRESOLVED exposures. |
| ASSETNOTE_IMPORT_TRIAGED_STATUS_NAME | `string` |  | string | `null` | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote TRIAGED exposures. |
| ASSETNOTE_IMPORT_RESOLVED_STATUS_NAME | `string` |  | string | `null` | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote RESOLVED exposures. |
| ASSETNOTE_IMPORT_IGNORED_STATUS_NAME | `string` |  | string | `null` | Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote IGNORED exposures. |
| ASSETNOTE_IMPORT_FIRST_RUN_RETRIEVAL_DATETIME | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"1970-01-01T00:00:00Z"` | ISO 8601 datetime indicating the earliest point in time from which assets and exposures should be retrieved from the Assetnote API. Used only on the connector's first run (i.e. before any state has been persisted). Defaults to the epoch (i.e. the full Assetnote catalogue) so existing deployments that never set this variable continue to start. |
