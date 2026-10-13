# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |  |
| DNSLYTICS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | DNSlytics API key (premium credits). Sent as the `apikey` query parameter, never logged. | ```0123456789abcdef0123456789abcdef``` |
| CONNECTOR_NAME | `string` |  | string | `"DNSlytics"` | The name of the connector. | ```DNSlytics``` |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator"]` | The entity types the connector enriches. Only Indicators with pattern type `dnslytics` are processed. | ```Indicator``` |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |  |
| DNSLYTICS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.dnslytics.net/"` | Base URL of the DNSlytics premium API. Only change it to point the connector at a local mock server for tests that must not spend credits. | ```https://api.dnslytics.net```, ```http://localhost:8000``` |
| DNSLYTICS_RESOLVE_HOSTING | `boolean` |  | boolean | `true` | Resolve each active domain (DNS A/AAAA), look up the AS of each IP (IP2ASN, free) and set a `provider:<AS name>` label. If false, only domains and the `dnslytics:active` / `dnslytics:dropped` label are created. | ```True```, ```False``` |
| DNSLYTICS_MAX_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"green"` | Do not enrich Indicators marked above this TLP level. | ```green```, ```amber``` |
| DNSLYTICS_OUTPUT_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object created by the connector. | ```clear```, ```green``` |
