# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ENISA EUVD"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["vulnerability"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT2H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT2H` for two hours). |
| EUVD_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://euvdservices.enisa.europa.eu/api"` | The base URL of the ENISA EUVD API. |
| EUVD_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | First run only: how far back (last-update) to pull, as an ISO 8601 duration (e.g. 'P30D' for 30 days). Subsequent runs resume from the connector's persisted state. |
| EUVD_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP (Traffic Light Protocol) marking applied to every object this connector creates in OpenCTI. |
| EUVD_INGEST_SOFTWARE | `boolean` |  | boolean | `false` | Enable/disable the import of Software observables and their 'has' relationship to each vulnerability. Off by default: a single vulnerability can reference many affected products, which increases the volume of objects created per run. |
