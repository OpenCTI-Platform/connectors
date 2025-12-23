# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MICROSOFT_DEFENDER_INTEL_TENANT_ID | `string` | ✅ | string |  | Your Azure App Tenant ID, see connector's README to help you find this information. |
| MICROSOFT_DEFENDER_INTEL_CLIENT_ID | `string` | ✅ | string |  | Your Azure App Client ID, see connector's README to help you find this information. |
| MICROSOFT_DEFENDER_INTEL_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your Azure App Client secret, see connector's README to help you find this information. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Defender Intel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["defender"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"live"` | The ID of the live stream to connect to. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| MICROSOFT_DEFENDER_INTEL_LOGIN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://login.microsoft.com/"` | Login URL for Microsoft which is `https://login.microsoft.com` |
| MICROSOFT_DEFENDER_INTEL_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.securitycenter.microsoft.com/"` | The resource the API will use which is `https://api.securitycenter.microsoft.com` |
| MICROSOFT_DEFENDER_INTEL_RESOURCE_PATH | `string` |  | string | `"/api/indicators"` | The request URL that will be used which is `/api/indicators` |
| MICROSOFT_DEFENDER_INTEL_EXPIRE_TIME | `integer` |  | integer | `30` | Number of days for your indicator to expire in Sentinel. |
| MICROSOFT_DEFENDER_INTEL_ACTION | `string` |  | `Warn` `Block` `Audit` `Alert` `AlertAndBlock` `BlockAndRemediate` `Allowed` | `"Alert"` | The action to apply if the indicator is matched from within the targetProduct security tool. `BlockAndRemediate` is not compatible with network indicators (see: https://learn.microsoft.com/en-us/defender-endpoint/indicator-manage) |
| MICROSOFT_DEFENDER_INTEL_PASSIVE_ONLY | `boolean` |  | boolean | `false` | Determines if the indicator should trigger an event that is visible to an end-user. When set to `True` security tools will not notify the end user that a 'hit' has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. |
