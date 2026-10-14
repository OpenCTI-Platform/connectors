# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| WHOISFREAKS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | WhoisFreaks API key. |
| CONNECTOR_NAME | `string` |  | string | `"WhoisFreaks"` | Display name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["indicator", "domain-name"]` | OpenCTI entity types imported by the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | Time between connector runs. |
| WHOISFREAKS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://files.whoisfreaks.com/v3.4/stream"` | WhoisFreaks threat-feed stream API base URL. |
| WHOISFREAKS_STATUS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://files.whoisfreaks.com"` | WhoisFreaks API status base URL. |
| WHOISFREAKS_FEED_TYPES | `array` |  | `malware` `phishing` `spam` | `["malware", "phishing", "spam"]` | Threat feeds to import (subset of: malware, phishing, spam). Leave empty or omit feeds you are not subscribed to. |
| WHOISFREAKS_NRD_FEED_TYPES | `array` |  | `nrd_gtld_with_whois` `nrd_cctld_with_whois` `nrd_gtld_without_whois` `nrd_cctld_without_whois` | `["nrd_gtld_with_whois", "nrd_cctld_with_whois", "nrd_gtld_without_whois", "nrd_cctld_without_whois"]` | NRD feeds to import. Valid values: nrd_gtld_with_whois, nrd_cctld_with_whois, nrd_gtld_without_whois, nrd_cctld_without_whois. Only enable feeds covered by your subscription. |
| WHOISFREAKS_NRD_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://files.whoisfreaks.com/v3.3/stream/domainer"` | WhoisFreaks NRD stream API base URL. |
| WHOISFREAKS_PAGE_LIMIT | `integer` |  | `1 <= x <= 100000` | `5000` | Number of CSV records requested per page. Higher values reduce HTTP overhead; keep within API limits and available memory (recommended 5000-10000 for large feeds). |
| WHOISFREAKS_NRD_TIMEOUT | `integer` |  | `1 <= x ` | `180` | HTTP timeout in seconds for NRD feed requests. |
| WHOISFREAKS_THREAT_TIMEOUT | `integer` |  | `1 <= x ` | `180` | HTTP timeout in seconds for threat-feed requests. |
| WHOISFREAKS_MAX_RETRIES | `integer` |  | `0 <= x <= 20` | `5` | Max HTTP retries on transient errors (429/5xx). |
| WHOISFREAKS_RETRY_BACKOFF_SECONDS | `number` |  | `0.1 <= x ` | `2.0` | Base seconds for exponential backoff between retries. |
| WHOISFREAKS_CHECKPOINT_EVERY_PAGES | `integer` |  | `1 <= x ` | `10` | Update the in-memory offset every N pages; the connector persists state at the end of its callback. |
| WHOISFREAKS_IMPORT_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | Latest-snapshot floor date; snapshots older than this date are skipped. This does not trigger historical backfill. Accepts an ISO-8601 date-time or relative duration such as P7D. |
| WHOISFREAKS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to imported STIX objects. |
| WHOISFREAKS_CREATE_INDICATORS_FOR_NRD | `boolean` |  | boolean | `false` | When true, create Indicator + based-on for NRD domains. When false, only Domain-Name observables are created (recommended for high-volume NRD feeds). |
