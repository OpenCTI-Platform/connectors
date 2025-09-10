# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GREYNOISE_FEED_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key to connect to Greynoise. |
| OPENCTI_JSON_LOGGING | `boolean` |  | boolean | `true` | Whether to format logs as JSON or not. |
| OPENCTI_SSL_VERIFY | `boolean` |  | boolean | `false` | Whether to check SSL certificate or not. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_NAME | `string` |  | string | `"GreyNoise Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["greynoisefeed"]` | The scope of the connector, e.g. 'greynoise'. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_EXPOSE_METRICS | `boolean` |  | boolean | `false` | Whether to expose metrics or not. |
| CONNECTOR_METRICS_PORT | `integer` |  | integer | `9095` | The port to expose metrics. |
| CONNECTOR_ONLY_CONTEXTUAL | `boolean` |  | boolean | `false` | Whether to expose metrics or not. |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `false` | Connector run-and-terminate flag. |
| CONNECTOR_VALIDATE_BEFORE_IMPORT | `boolean` |  | boolean | `false` | Whether to validate data before import or not. |
| CONNECTOR_QUEUE_PROTOCOL | `string` |  | string | `"amqp"` | The queue protocol to use. |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | integer | `500` | Connector queue max size in Mbytes. Default to pycti value. |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `true` | Connector send-to-queue flag. Default to True. |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `false` | Connector send-to-directory flag. |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` | Connector send-to-directory path. |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | integer | `7` | Connector send-to-directory retention. |
| GREYNOISE_FEED_FEED_TYPE | `string` |  | `benign` `malicious` `suspicious` `benign+malicious` `malicious+suspicious` `benign+suspicious+malicious` `all` | `"malicious"` | Type of feed to import. |
| GREYNOISE_FEED_LIMIT | `integer` |  | integer | `10000` | Max number of indicators to ingest. |
| GREYNOISE_FEED_IMPORT_METADATA | `boolean` |  | boolean | `false` | Import metadata (cities, sightings, etc.). ⚠️ Can generate a lot of data. |
| GREYNOISE_FEED_IMPORT_DESTINATION_SIGHTINGS | `boolean` |  | boolean | `false` | Import indicator's countries (from metadata) as a Sighting. |
| GREYNOISE_FEED_INDICATOR_SCORE_MALICIOUS | `integer` |  | `0 <= x <= 100` | `75` | Default indicator score for malicious indicators. |
| GREYNOISE_FEED_INDICATOR_SCORE_SUSPICIOUS | `integer` |  | `0 <= x <= 100` | `50` | Default indicator score for suspicious indicators. |
| GREYNOISE_FEED_INDICATOR_SCORE_BENIGN | `integer` |  | `0 <= x <= 100` | `20` | Default indicator score for benign indicators. |
