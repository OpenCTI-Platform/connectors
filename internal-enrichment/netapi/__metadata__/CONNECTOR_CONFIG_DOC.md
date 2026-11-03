# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"NetAPI"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Domain-Name", "Hostname", "Url"]` | The observable types the connector enriches. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enrich new observables automatically. Without an API token the NetAPI JSON API allows 30 requests a minute and 1,000 a day per IP address, so this is off by default. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| NETAPI_API_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional NetAPI API token (the token of any account, free accounts included). The lookups are free without one; a token only raises the request limits. |
| NETAPI_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://netapi.com/api-json/"` | Base URL of the NetAPI JSON API. |
| NETAPI_TIMEOUT | `integer` |  | `1 <= x ` | `30` | HTTP request timeout in seconds. |
| NETAPI_INCLUDE_RANK | `boolean` |  | boolean | `true` | Add the position of a listed domain in the NetAPI Top 1M to the note (one more request per listed domain or hostname). |
| NETAPI_UPDATE_SCORE | `boolean` |  | boolean | `false` | Write `score` to the observable when it is listed in the compromised feed now. The existing score is overwritten. Off by default. |
| NETAPI_SCORE | `integer` |  | `0 <= x <= 100` | `80` | Score written to a currently listed observable when `update_score` is true. |
| NETAPI_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to the note, in addition to the markings of the source observable. The feed is public data (CC BY 4.0). |
