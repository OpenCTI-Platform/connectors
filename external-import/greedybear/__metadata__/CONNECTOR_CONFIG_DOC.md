# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GREEDYBEAR_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | GreedyBear base URL, e.g. https://greedybear.example.com |
| CONNECTOR_NAME | `string` |  | string | `"GreedyBear"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Autonomous-System", "Location", "Infrastructure"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Interval between two runs of the connector. |
| GREEDYBEAR_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | GreedyBear API token (used for advanced and ASN feeds). Leave empty to use only the public standard feed (no auth required). |
| GREEDYBEAR_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"green"` | Default TLP level for all imported entities. |
| GREEDYBEAR_OPERATOR_NAME | `string` |  | string | `"Honeypot Operator"` | Name of the organization operating the honeypots. This becomes the 'created by' identity in OpenCTI. |
| GREEDYBEAR_OPERATOR_DESCRIPTION | `string` |  | string | `null` | Optional description of the honeypot operator. |
| GREEDYBEAR_OPERATOR_URL | `string` |  | string | `null` | Optional URL of the honeypot operator (website, GitHub, etc.). |
| GREEDYBEAR_FEED_TYPE | `string` |  | string | `"all"` | Honeypot feed type. Comma-separated names or 'all'. Valid values: all, cowrie, dionaea, adbhoney, ciscoasa, conpot, ... |
| GREEDYBEAR_ATTACK_TYPE | `string` |  | string | `"all"` | Attack type filter: 'scanner', 'payload_request', or 'all'. |
| GREEDYBEAR_IOC_TYPE | `string` |  | string | `"all"` | IoC type filter: 'ip', 'domain', or 'all'. |
| GREEDYBEAR_PRIORITIZE | `string` |  | string | `"recent"` | Standard feed prioritization: 'recent', 'persistent', 'likely_to_recur', 'most_expected_hits'. |
| GREEDYBEAR_INCLUDE_MASS_SCANNERS | `boolean` |  | boolean | `false` | Include IoCs flagged as mass scanners. |
| GREEDYBEAR_INCLUDE_TOR_EXIT_NODES | `boolean` |  | boolean | `true` | Include IoCs flagged as Tor exit nodes. |
| GREEDYBEAR_MAX_AGE | `integer` |  | integer | `3` | Maximum age of entries in days (advanced feed, default 3). |
| GREEDYBEAR_FEED_SIZE | `integer` |  | integer | `5000` | Maximum number of IoCs to import per run (default 5000). |
| GREEDYBEAR_MIN_SCORE | `number` |  | number | `null` | Minimum recurrence_probability (0.0-1.0). None means no filter. |
| GREEDYBEAR_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Create STIX Indicators for every imported observable. Indicators are linked via based-on to the observable and via indicates to the MITRE Attack Pattern (if known). |
| GREEDYBEAR_DEEP_ENRICH | `boolean` |  | boolean | `false` | Per-IoC enrichment call adding the actual destination ports and the days-seen count to the Note, plus FireHOL blocklist categories as labels. One extra API call per IoC - slow for large feeds; needs an API key. |
