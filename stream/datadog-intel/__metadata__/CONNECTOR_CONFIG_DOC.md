# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| DATADOG_INTEL_INTEGRATION_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Datadog's API URL as provided by the integration. If your Datadog site is `https://app.datadoghq.com`, use `https://api.datadoghq.com/api/v2/security/threat-intel-feed` |
| DATADOG_INTEL_DD_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Datadog's API key. Sent on every request as the `dd-api-key` header to authenticate against `integration_api_url` |
| DATADOG_INTEL_DD_APPLICATION_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Datadog's application key. Sent on every request as the `dd-application-key` header to authenticate against `integration_api_url` |
| CONNECTOR_NAME | `string` |  | string | `"DatadogIntelConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| DATADOG_INTEL_INDICATOR_TYPE | `array` |  | string | `["ip_address"]` | Types of indicators to send to the API. Accepted values: 'ip_address', 'domain', 'sha256'. |
