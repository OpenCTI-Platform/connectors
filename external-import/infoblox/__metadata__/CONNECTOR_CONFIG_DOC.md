# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| INFOBLOX_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API key used to authenticate against the Infoblox TIDE API. |
| CONNECTOR_NAME | `string` |  | string |  | `"Infoblox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["infoblox"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT12H"` | The period of time to await between two runs of the connector. |
| INFOBLOX_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://csp.infoblox.com/tide/api/data/threats"` | The Infoblox TIDE API endpoint to fetch threat data from. |
| INFOBLOX_IOC_LIMIT | `string` |  | string |  | `"10000"` | Limit of IOCs to import (for each IOC type). |
| INFOBLOX_MARKING_DEFINITION | `string` |  | string |  | `"TLP:AMBER+STRICT"` | The marking definition to apply to imported data (e.g. 'TLP:AMBER+STRICT'). |
| INFOBLOX_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
