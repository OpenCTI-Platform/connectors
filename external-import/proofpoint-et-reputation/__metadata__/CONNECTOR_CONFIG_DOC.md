# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| PROOFPOINT_ET_REPUTATION_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token for authentication with the ProofPoint ET Reputation API. |
| CONNECTOR_NAME | `string` |  | string | `"ProofPoint ET Reputation"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "Domain-Name"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| PROOFPOINT_ET_REPUTATION_CREATE_INDICATOR | `boolean` |  | boolean | `true` | Whether indicators should be created from the reputation data. |
| PROOFPOINT_ET_REPUTATION_MIN_SCORE | `integer` |  | `20 <= x <= 100` | `20` | Minimum score threshold for processing reputation data (20-100). |
