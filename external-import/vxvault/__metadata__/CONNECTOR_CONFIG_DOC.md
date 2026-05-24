# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"VX Vault URL list"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["vxvault"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P3D"` | The period of time to await between two runs of the connector. |
| VXVAULT_URL | `string` |  | string |  | `"https://vxvault.net/URL_List.php"` | The URL of the VXVault dataset to fetch. |
| VXVAULT_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | If true, create indicators from the imported URLs. |
| VXVAULT_SSL_VERIFY | `boolean` |  | boolean |  | `false` | Whether to verify SSL certificates when fetching the dataset. |
| VXVAULT_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
