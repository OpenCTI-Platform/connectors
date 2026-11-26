# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CYBERTHREATEXCHANGE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API key used to authenticate to the Cyber Threat Exchange API. |
| CONNECTOR_NAME | `string` |  | string |  | `"CyberThreatExchange"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["cyberthreatexchange"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| CYBERTHREATEXCHANGE_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://api.cyberthreatexchange.com/"` | The base URL of the Cyber Threat Exchange API. |
| CYBERTHREATEXCHANGE_FEED_IDS | `array` |  | string |  | `[]` | Comma-separated list of the IDs of the subscribed feeds to import (e.g. 'f0895eb3-7d90-4b45-8664-a7e157ba880f,b63c638e-43e6-43d4-bfac-5b71c264b132'). At least one feed ID is required: the connector stops at startup otherwise. |
| CYBERTHREATEXCHANGE_INTERVAL_HOURS | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
