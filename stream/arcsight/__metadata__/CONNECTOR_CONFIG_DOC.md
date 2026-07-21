# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the OpenCTI live stream to connect to. |
| ARCSIGHT_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the ArcSight ESM Manager (e.g. https://arcsight.example.com:8443). |
| ARCSIGHT_USERNAME | `string` | ✅ | string |  | ArcSight ESM user name. |
| ARCSIGHT_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ArcSight ESM user password. |
| ARCSIGHT_ACTIVE_LIST_ID | `string` | ✅ | string |  | Resource ID of the ArcSight Active List that receives the IOCs. |
| CONNECTOR_NAME | `string` |  | string | `"ArcSight"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["arcsight"]` | The scope of the connector, used to filter the live stream events. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| ARCSIGHT_VALUE_COLUMN | `string` |  | string | `"value"` | Name of the Active List column that stores the IOC value. |
| ARCSIGHT_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the ArcSight ESM Manager. |
