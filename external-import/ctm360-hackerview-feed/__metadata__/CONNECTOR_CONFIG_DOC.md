# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CTM360_HACKERVIEW_FEED_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for HackerView authentication. |
| CONNECTOR_NAME | `string` |  | string | `"CTM360-HackerView"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["CTM360-HackerView"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| CTM360_HACKERVIEW_FEED_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://hackerview.ctm360.com/"` | HackerView API base URL. |
| CTM360_HACKERVIEW_FEED_IMPORT_ISSUES | `boolean` |  | boolean | `true` | Enable importing security issues. |
| CTM360_HACKERVIEW_FEED_IMPORT_RESOLVED_ISSUES | `boolean` |  | boolean | `true` | Enable importing resolved issues. |
| CTM360_HACKERVIEW_FEED_IMPORT_DOMAIN_ASSETS | `boolean` |  | boolean | `true` | Enable importing domain assets. |
| CTM360_HACKERVIEW_FEED_IMPORT_HOST_ASSETS | `boolean` |  | boolean | `true` | Enable importing hostname assets. |
| CTM360_HACKERVIEW_FEED_IMPORT_IP_ASSETS | `boolean` |  | boolean | `true` | Enable importing IP address assets. |
| CTM360_HACKERVIEW_FEED_STATUS_POLL_INTERVAL | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | ISO-8601 duration between status polling cycles (default: PT1H). |
| CTM360_HACKERVIEW_FEED_ENABLE_STATUS_TRACKING | `boolean` |  | boolean | `true` | Enable background polling for issue status changes. |
