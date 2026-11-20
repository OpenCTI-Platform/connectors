# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CTM360_CBS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | API key for CyberBlindSpot authentication. |
| CONNECTOR_NAME | `string` |  | string |  | `"CTM360-CyberBlindSpot"` |  |
| CONNECTOR_SCOPE | `array` |  | string |  | `["CTM360-CyberBlindSpot"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P1D"` | The period of time to await between two runs of the connector. |
| CTM360_CBS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"https://cbs.ctm360.com"` | CyberBlindSpot API base URL. |
| CTM360_CBS_IMPORT_INCIDENTS | `boolean` |  | boolean |  | `true` | Enable importing incidents. |
| CTM360_CBS_IMPORT_MALWARE_LOGS | `boolean` |  | boolean |  | `true` | Enable importing malware logs. |
| CTM360_CBS_IMPORT_BREACHED_CREDENTIALS | `boolean` |  | boolean |  | `true` | Enable importing breached credentials. |
| CTM360_CBS_IMPORT_CARD_LEAKS | `boolean` |  | boolean |  | `true` | Enable importing card leaks. |
| CTM360_CBS_IMPORT_DOMAIN_PROTECTION | `boolean` |  | boolean |  | `true` | Enable importing domain protection findings. |
| CTM360_CBS_STATUS_POLL_INTERVAL | `integer` |  | `0 < x ` |  | `3600` | Interval in seconds between status polling cycles (default: 1h). |
| CTM360_CBS_ENABLE_STATUS_TRACKING | `boolean` |  | boolean |  | `true` | Enable background polling for incident status changes. |
| CTM360_CBS_IMPORT_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
