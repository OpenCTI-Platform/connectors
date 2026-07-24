# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| URLSCAN_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The Urlscan API key. |
| CONNECTOR_NAME | `string` |  | string | `"Urlscan"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["urlscan"]` | The scope of the connector, e.g. 'urlscan'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_INTERVAL | `integer` |  | integer | `86400` | Interval between two runs of the connector, in seconds. |
| CONNECTOR_LOOKBACK | `integer` |  | integer | `3` | How far to look back in days if the connector has never run or its last run is older than this value. |
| URLSCAN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://urlscan.io/api/v1/pro/phishfeed?format=json"` | The Urlscan feed URL to query. |
| URLSCAN_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Whether to create indicators for imported observables. |
| URLSCAN_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `true` | Whether to update data already ingested into the platform. |
| URLSCAN_DEFAULT_TLP | `string` |  | string | `"white"` | Default TLP marking applied to imported data. |
| URLSCAN_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer | `50` | Default x_opencti_score applied to imported data. |
| URLSCAN_X_OPENCTI_SCORE_DOMAIN | `integer` |  | integer | `null` | Optional x_opencti_score for domain-name observables. |
| URLSCAN_X_OPENCTI_SCORE_URL | `integer` |  | integer | `null` | Optional x_opencti_score for url observables. |
