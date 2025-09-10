# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

> ⚠️ Additional properties are not allowed.

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  |
| CONNECTOR_NAME | `string` | ✅ | Length: `string >= 1` |  | Name of the connector |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector |
| OPENCTI_JSON_LOGGING | `boolean` |  | boolean | `true` |  |
| OPENCTI_SSL_VERIFY | `boolean` |  | boolean | `false` |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT10M"` | Duration between two scheduled runs of the connector (ISO 8601 format) |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warning` `error` `critical` |  |  |
| CONNECTOR_EXPOSE_METRICS | `boolean` |  | boolean | `false` |  |
| CONNECTOR_METRICS_PORT | `integer` |  | integer | `9095` |  |
| CONNECTOR_ONLY_CONTEXTUAL | `boolean` |  | boolean | `false` |  |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `false` |  |
| CONNECTOR_VALIDATE_BEFORE_IMPORT | `boolean` |  | boolean | `false` |  |
| CONNECTOR_QUEUE_PROTOCOL | `string` |  | string | `"amqp"` |  |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | integer | `500` |  |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `true` |  |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `false` |  |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` |  |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | integer | `7` |  |
| CONNECTOR_PULL_HISTORY | `boolean` |  | boolean | `false` | Whether to pull historic data |
| CONNECTOR_HISTORY_START_YEAR | `integer` |  | integer | `2023` | The year to start from |
| CONNECTOR_CREATE_THREAT_ACTOR | `boolean` |  | boolean | `false` | Whether to create a Threat Actor object |
