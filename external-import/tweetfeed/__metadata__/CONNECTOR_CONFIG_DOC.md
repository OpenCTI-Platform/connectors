# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"TweetFeed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| TWEETFEED_CONFIDENCE_LEVEL | `integer` |  | integer | `25` | Score applied to imported data, from 0 (Unknown) to 100 (Fully trusted). |
| TWEETFEED_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Whether to create indicators from the imported IOCs. |
| TWEETFEED_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create observables from the imported IOCs. |
| TWEETFEED_INTERVAL | `integer` |  | integer | `1` | Interval, in days, between two runs of the connector. |
| TWEETFEED_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `true` | Whether to update data already present in OpenCTI. |
| TWEETFEED_ORG_NAME | `string` |  | string | `"Tweetfeed"` | Name of the author organization created in OpenCTI. |
| TWEETFEED_ORG_DESCRIPTION | `string` |  | string | `"Tweetfeed, a connector to import IOC from Twitter."` | Description of the author organization created in OpenCTI. |
| TWEETFEED_DAYS_BACK_IN_TIME | `integer` |  | integer | `30` | Number of days to retrieve data back in time. |
