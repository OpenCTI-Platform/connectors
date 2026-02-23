# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GREYNOISE_FEED_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key to connect to Greynoise. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_NAME | `string` |  | string | `"GreyNoise Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["greynoisefeed"]` | The scope of the connector, e.g. 'greynoise'. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| GREYNOISE_FEED_FEED_TYPE | `string` |  | `benign` `malicious` `suspicious` `benign+malicious` `malicious+suspicious` `benign+suspicious+malicious` `all` | `"malicious"` | Type of feed to import. |
| GREYNOISE_FEED_LIMIT | `integer` |  | integer | `10000` | Max number of indicators to ingest. |
| GREYNOISE_FEED_INDICATOR_SCORE_MALICIOUS | `integer` |  | `0 <= x <= 100` | `75` | Default indicator score for malicious indicators. |
| GREYNOISE_FEED_INDICATOR_SCORE_SUSPICIOUS | `integer` |  | `0 <= x <= 100` | `50` | Default indicator score for suspicious indicators. |
| GREYNOISE_FEED_INDICATOR_SCORE_BENIGN | `integer` |  | `0 <= x <= 100` | `20` | Default indicator score for benign indicators. |
