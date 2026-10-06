# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CRTSH_DOMAIN | `string` | ✅ | string |  | Domain to search certificates for (e.g. 'google.com'). |
| CONNECTOR_NAME | `string` |  | string | `"crt.sh"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crtsh"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_RUN_EVERY | `string` |  | [`^\d+[dhmsDHMS]$`](https://regex101.com/?regex=%5E%5Cd%2B%5BdhmsDHMS%5D%24) | `"1h"` | The period of time to await between two runs of the connector. Format: a number followed by a unit among 'd', 'h', 'm', 's' (e.g. '7d', '12h', '10m', '30s'). |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `false` | Whether to update existing data in OpenCTI. |
| CRTSH_LABELS | `string` |  | string | `"crtsh,osint"` | Comma-separated list of labels to add to the imported objects (e.g. 'crtsh,osint'). |
| CRTSH_MARKING_REFS | `string` |  | `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:RED` | `"TLP:WHITE"` | TLP marking to apply to the imported objects. |
| CRTSH_IS_EXPIRED | `boolean` |  | boolean | `false` | Whether to exclude expired certificates from the search. |
| CRTSH_IS_WILDCARD | `boolean` |  | boolean | `false` | Whether to apply a wildcard expression to the domain (search its subdomains). |
