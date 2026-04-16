# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| MICROSOFT_SENTINEL_INTEL_TENANT_ID | `string` | ✅ | string |  | Your Azure App Tenant ID, see the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INTEL_CLIENT_ID | `string` | ✅ | string |  | Your Azure App Client ID, see the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INTEL_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your Azure App Client secret, See the screenshot to help you find this information. |
| MICROSOFT_SENTINEL_INTEL_WORKSPACE_ID | `string` | ✅ | string |  | Your Azure Workspace ID |
| MICROSOFT_SENTINEL_INTEL_WORKSPACE_NAME | `string` | ✅ | string |  | The name of the log analytics workspace |
| MICROSOFT_SENTINEL_INTEL_SUBSCRIPTION_ID | `string` | ✅ | string |  | The subscription id where the Log Analytics is |
| CONNECTOR_NAME | `string` |  | string | `"MicrosoftSentinelIntel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["sentinel"]` | The scope of the stream connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| MICROSOFT_SENTINEL_INTEL_RESOURCE_GROUP | `string` |  | string | `"default"` | The name of the resource group where the log analytics is |
| MICROSOFT_SENTINEL_INTEL_SOURCE_SYSTEM | `string` |  | string | `"Opencti Stream Connector"` | The name of the source system displayed in Microsoft Sentinel |
| MICROSOFT_SENTINEL_INTEL_DELETE_EXTENSIONS | `boolean` |  | boolean | `true` | Delete the extensions in the stix bundle sent to the SIEM |
| MICROSOFT_SENTINEL_INTEL_EXTRA_LABELS | `array` |  | string | `[]` | Extra labels added to the bundle sent. String separated by comma |
| MICROSOFT_SENTINEL_INTEL_WORKSPACE_API_VERSION | `string` |  | string | `"2024-02-01-preview"` | API version of the Microsoft log analytics workspace interface |
| MICROSOFT_SENTINEL_INTEL_MANAGEMENT_API_VERSION | `string` |  | string | `"2025-03-01"` | API version of the Microsoft management interface |
| MICROSOFT_SENTINEL_INTEL_BATCH_MODE | `boolean` |  | boolean | `false` | Enable batch mode for bulk uploading STIX objects. When disabled (default), objects are sent individually in real-time. |
| MICROSOFT_SENTINEL_INTEL_BATCH_SIZE | `integer` |  | `1 <= x <= 100` | `100` | Maximum number of unique STIX objects to accumulate before flushing a batch. Only used when batch_mode is enabled. Maxed at 100 because the Sentinel Upload Indicators API rejects requests containing more than 100 STIX objects. |
| MICROSOFT_SENTINEL_INTEL_BATCH_TIMEOUT | `integer` |  | `1 <= x ` | `30` | Maximum time in seconds to wait before flushing a partial batch. Only used when batch_mode is enabled. |
| MICROSOFT_SENTINEL_INTEL_EVENT_TYPES | `array` |  | string | `["create", "update", "delete"]` | Comma-separated list of event types to process (create, update, delete). Defaults to all three; a single instance handles every event type. Restrict this only if you want to split the workload across dedicated instances. |
