# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"XposedOrNot"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Email-Addr"]` | The scope of the connector (observable types to enrich). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables. The keyless community API is rate limited (2/s, 25/hour per IP); keep disabled or configure an API key before enabling on busy platforms. |
| XPOSEDORNOT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional XposedOrNot API key (console.xposedornot.com). When set, the connector uses the commercial Plus API with higher rate limits. The connector is fully functional without it. |
| XPOSEDORNOT_API_BASE_URL | `string` |  | [`^https://`](https://regex101.com/?regex=%5Ehttps%3A%2F%2F) | `"https://api.xposedornot.com"` | Base URL of the free XposedOrNot community API. Must use https: the observable's email address is sent to this endpoint. It does not affect the Plus API, whose endpoint is fixed and is used instead whenever XPOSEDORNOT_API_KEY is set. |
| XPOSEDORNOT_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP of an observable the connector is allowed to enrich. The observable's email address is sent to the XposedOrNot API. |
| XPOSEDORNOT_MAX_NOTE_BREACHES | `integer` |  | `0 <= x ` | `50` | Maximum number of breaches rendered in the summary note's table, newest first. A line names how many more were found. Set 0 to render every breach; large values make the note hard to read. |
| XPOSEDORNOT_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | Minimum Traffic Light Protocol (TLP) level applied to the objects imported into OpenCTI. The note carries the stricter of this level and the source observable's own marking. Results contain personal data; a restrictive TLP is recommended. 'white' is the deprecated alias of 'clear'. |
