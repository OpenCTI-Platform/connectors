# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |  |
| CYBLE_VISION_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Cyble Vision API bearer token. |  |
| CONNECTOR_NAME | `string` |  | string | `"Cyble Vision"` | Display name in OpenCTI. |  |
| CONNECTOR_SCOPE | `array` |  | string | `["Incident", "Report", "Note", "Indicator", "Vulnerability", "Intrusion-Set", "Domain-Name", "IPv4-Addr", "Url", "X509-Certificate", "User-Account"]` | Descriptive entity types this connector imports. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Wait time between runs, as an ISO-8601 duration. |  |
| CYBLE_VISION_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://bifrost.cyble.ai"` | Cyble Vision API base URL. |  |
| CYBLE_VISION_IMPORT_SINCE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | Lookback on the first run. Absolute ISO datetime or relative duration such as P7D. |  |
| CYBLE_VISION_ALERT_SERVICES | `array` |  | string | `[]` | Allow-list of Vision service names. Empty means every entitled service from GET /y/services. | ```ssl_expiry,darkweb_data_breaches,advisory,flash_report``` |
| CYBLE_VISION_EXCLUDE_STATUSES | `array` |  | string | `["FALSE_POSITIVE"]` | Alert statuses to omit from import. |  |
| CYBLE_VISION_PAGE_SIZE | `integer` |  | `1 <= x <= 500` | `100` | Alerts API page size (skip/take). |  |
| CYBLE_VISION_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every imported object. |  |
| CYBLE_VISION_PORTAL_URL_TEMPLATE | `string` |  | string | `"https://cyble.ai/alerts/{service}?id=[\"{alert_id}\"]"` | Deep-link template. Placeholders: {service}, {alert_id}. |  |
| CYBLE_VISION_ENGINE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.cyble.ai"` | Cyble engine API base URL for advisories, newsfeed, and newsflash. |  |
| CYBLE_VISION_ENABLE_ADVISORIES | `boolean` |  | boolean | `true` | Import research advisories from the engine API. |  |
| CYBLE_VISION_ENABLE_NEWSFEED | `boolean` |  | boolean | `true` | Import newsfeed articles from the engine API. |  |
| CYBLE_VISION_ENABLE_NEWSFLASH | `boolean` |  | boolean | `true` | Import newsflash spot reports from the engine API. |  |
| CYBLE_VISION_ENGINE_PAGE_SIZE | `integer` |  | `1 <= x <= 200` | `50` | Page size for engine document APIs. |  |
