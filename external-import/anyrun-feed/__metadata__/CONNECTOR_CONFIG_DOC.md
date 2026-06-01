# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ANY.RUN TI Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["stix2"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `false` | Whether to update data already ingested into the platform. |
| ANYRUN_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ANY.RUN TI Feeds API key. See 'Generate your API key' section in the README file. |
| ANYRUN_FEED_FETCH_INTERVAL | `integer` |  | integer | `120` | Specify feed fetch interval in minutes. |
| ANYRUN_FEED_FETCH_DEPTH | `integer` |  | integer | `90` | Specify feed fetch depth in days. |
