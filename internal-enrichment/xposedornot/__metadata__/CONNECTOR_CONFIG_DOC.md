# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"XposedOrNot"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Email-Addr"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables. The keyless community API is rate limited (2/s, 25/hour per IP); keep disabled or configure an API key before enabling on busy platforms. |
| XPOSEDORNOT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Optional XposedOrNot API key (console.xposedornot.com). When set, the connector uses the commercial Plus API with higher rate limits. The connector is fully functional without it. |
| XPOSEDORNOT_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.xposedornot.com"` | Base URL of the free XposedOrNot community API. |
| XPOSEDORNOT_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP of an observable the connector is allowed to enrich. The observable's email address is sent to the XposedOrNot API. |
| XPOSEDORNOT_TLP_LEVEL | `string` |  | `clear` `green` `amber` `amber+strict` `red` | `"amber"` | Traffic Light Protocol (TLP) level applied to the objects imported into OpenCTI. Results contain personal data; a restrictive TLP is recommended. |
