# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| OSINT_INDUSTRIES_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate requests to the OSINT Industries service. |
| CONNECTOR_NAME | `string` |  | string | `"OSINT Industries"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Email-Addr", "Phone-Number", "User-Account", "Cryptocurrency-Wallet"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables for OpenCTI. Keep disabled for this quota-based paid source to avoid depleting API credits. |
| OSINT_INDUSTRIES_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.osint.industries"` | Base URL of the OSINT Industries API. |
| OSINT_INDUSTRIES_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Traffic Light Protocol (TLP) level applied to the objects imported into OpenCTI. Results contain personal data; a restrictive TLP is recommended. |
| OSINT_INDUSTRIES_PREMIUM | `boolean` |  | boolean | `false` | If enabled, queries additional premium modules. This consumes more API credits. |
