# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| OSINT_INDUSTRIES_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key used to authenticate against the OSINT Industries API. |
| CONNECTOR_NAME | `string` |  | string | `"OSINT Industries"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Email-Addr", "Phone-Number", "User-Account", "Cryptocurrency-Wallet"]` | The scope of the connector, i.e. the observable types it can enrich. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| OSINT_INDUSTRIES_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.osint.industries/"` | The base URL of the OSINT Industries API. |
| OSINT_INDUSTRIES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | The TLP marking applied to the objects produced by the connector. |
| OSINT_INDUSTRIES_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | The maximum TLP level of an observable the connector is allowed to enrich. Observables marked above this level are skipped and their value is never sent to the OSINT Industries API. |
| OSINT_INDUSTRIES_PREMIUM | `boolean` |  | boolean | `false` | Whether to query the premium modules. Enabling it returns more results but consumes more API credits. |
