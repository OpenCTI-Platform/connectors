# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| ONYPHE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The ONYPHE API key. |
| CONNECTOR_NAME | `string` |  | string |  | `"ONYPHE"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["ipv4-addr", "ipv6-addr", "indicator", "hostname", "x509-certificate", "text"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| ONYPHE_BASE_URL | `string` |  | string |  | `"https://www.onyphe.io/api/v2/"` | The ONYPHE API base URL (with a trailing slash). |
| ONYPHE_CATEGORY | `string` |  | string |  | `"ctiscan"` | The ONYPHE data category to query: `ctiscan` or `riskscan`. |
| ONYPHE_TIME_SINCE | `string` |  | string |  | `"1w"` | The time window of the ONYPHE data to retrieve (OQL `-since` value, e.g. `1w`). |
| ONYPHE_DEFAULT_SCORE | `integer` |  | integer |  | `50` | The default score of the created observables. |
| ONYPHE_IMPORT_SEARCH_RESULTS | `boolean` |  | boolean |  | `true` | Whether to import the search results as observables when enriching an indicator. |
| ONYPHE_CREATE_NOTE | `boolean` |  | boolean |  | `false` | Whether to attach the enrichment summary as a note on observables, instead of their description. |
| ONYPHE_IMPORT_FULL_DATA | `boolean` |  | boolean |  | `false` | Whether to import the full raw application response text (can produce large data). |
| ONYPHE_PIVOT_THRESHOLD | `integer` |  | integer |  | `10` | The maximum number of results of an observable enrichment: above it, nothing is imported. |
| ONYPHE_INDICATOR_MAX_RESULTS | `integer` |  | integer |  | `1000` | The maximum number of results of an indicator enrichment: above it, the query is considered too imprecise and nothing is imported. |
| ONYPHE_PATTERN_TYPE | `string` |  | string |  | `"onyphe"` | The vocabulary entry of the ONYPHE indicator pattern type. |
| ONYPHE_ENRICHMENT_TYPES | `array` |  | string |  | `[]` | Comma-separated list of OpenCTI object types to create during enrichment, empty for all types. Valid values: Domain-Name, Hostname, IPv4-Address, IPv6-Address, Autonomous-System, X509-Certificate, Text, Vulnerability. |
| ONYPHE_TEXT_FINGERPRINTS | `array` |  | string |  | `[]` | Comma-separated list of fingerprint pivot labels to create as Text observables, empty for the default sha256-preferred set (e.g. hhhash-sha256, favicon-sha256, ssh-fingerprint-sha256). |
| ONYPHE_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
