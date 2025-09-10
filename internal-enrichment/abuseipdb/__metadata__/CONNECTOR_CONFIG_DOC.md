# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| ABUSEIPDB_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate requests to the AbuseIPDB service. |
| CONNECTOR_NAME | `string` |  | string | `"AbuseIPDB"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"IPv4-Addr"` | The scope defines the set of entity types that the enrichment connector is allowed to process. |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | Enables or disables automatic enrichment of observables for OpenCTI. |
| ABUSEIPDB_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. |
