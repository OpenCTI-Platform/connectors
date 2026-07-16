# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | Yes | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | Yes | string |  | The API token to connect to OpenCTI. |
| FLOWTRIQ_API_KEY | `string` | Yes | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your Flowtriq deploy token (64-character hex string). |
| CONNECTOR_NAME | `string` |  | string | `"Flowtriq DDoS Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["flowtriq"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| FLOWTRIQ_API_URL | `string` |  | string | `"https://app.flowtriq.com"` | Flowtriq API base URL. |
| FLOWTRIQ_INCIDENT_STATUS | `string` |  | `active` `resolved` `false_positive` `` | `"resolved"` | Filter incidents by status. Leave empty to fetch all statuses. |
| FLOWTRIQ_INCIDENT_SEVERITY | `array` |  | string | `[]` | Comma-separated severity levels to import (critical, high, medium, low). Leave empty for all. |
| FLOWTRIQ_CREATE_INDICATOR | `boolean` |  | boolean | `true` | Whether to create Indicator objects from observables. |
| FLOWTRIQ_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"green"` | TLP marking for imported data. |
| FLOWTRIQ_IMPORT_LIMIT | `integer` |  | integer | `100` | Maximum number of incidents to fetch per run. |
| FLOWTRIQ_MIN_SEVERITY | `string` |  | `low` `medium` `high` `critical` `` | `""` | Minimum severity threshold. Incidents below this level are skipped. |
