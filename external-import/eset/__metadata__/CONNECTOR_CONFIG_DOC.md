# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ESET_USERNAME | `string` | ✅ | string |  | ESET Threat Intelligence username. |
| ESET_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ESET Threat Intelligence password. |
| CONNECTOR_NAME | `string` |  | string | `"ESET Cyber Threat Intelligence"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["eset"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `false` | Whether to update data already present in OpenCTI. |
| ESET_API_URL | `string` |  | string | `"eti.eset.com"` | Hostname of the ESET Threat Intelligence TAXII service. |
| ESET_COLLECTIONS | `array` |  | string | `["ei.misp", "ei.cc", "ei.urls"]` | Comma-separated list of ESET TAXII collections to import. |
| ESET_IMPORT_APT_REPORTS | `boolean` |  | boolean | `true` | Whether to import ESET APT reports. |
| ESET_IMPORT_START_DATE | `string` |  | string | `"2022-04-01"` | Date from which data is imported on the first run (e.g. 2022-04-01). |
| ESET_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create observables from imported indicators. |
| ESET_INTERVAL | `integer` |  | integer | `60` | Interval, in minutes, between two runs of the connector. |
