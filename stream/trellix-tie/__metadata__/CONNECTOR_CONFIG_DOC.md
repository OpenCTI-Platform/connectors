# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| TRELLIX_TIE_DXL_CONFIG_PATH | `string` | ✅ | string |  | Path to the ePO-provisioned OpenDXL configuration file (dxlclient.config) describing the DXL brokers and client certificate. |
| CONNECTOR_NAME | `string` |  | string | `"Trellix TIE"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["trellix-tie"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_ID | `string` |  | string | `"live"` | The ID of the OpenCTI live stream to connect to. |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| TRELLIX_TIE_TRUST_LEVEL | `string` |  | `KNOWN_MALICIOUS` `MOST_LIKELY_MALICIOUS` `MIGHT_BE_MALICIOUS` `UNKNOWN` `MIGHT_BE_TRUSTED` `MOST_LIKELY_TRUSTED` `KNOWN_TRUSTED` `KNOWN_TRUSTED_INSTALLER` `NOT_SET` | `"KNOWN_MALICIOUS"` | Trust level to set on the TIE enterprise reputation for pushed hashes. |
| TRELLIX_TIE_COMMENT | `string` |  | string | `"Set by OpenCTI"` | Comment attached to the reputation set in TIE. |
