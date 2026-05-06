# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | ID of the live stream to connect to (created in the OpenCTI UI). |
| SECOPS_SIEM_PROJECT_ID | `string` | ✅ | string |  | Google Cloud project ID for the SecOps SIEM instance. |
| SECOPS_SIEM_PROJECT_INSTANCE | `string` | ✅ | string |  | Google SecOps SIEM project instance identifier. |
| SECOPS_SIEM_PRIVATE_KEY_ID | `string` | ✅ | string |  | Service account private key ID. |
| SECOPS_SIEM_PRIVATE_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Service account private key (PEM format). |
| SECOPS_SIEM_CLIENT_EMAIL | `string` | ✅ | string |  | Service account client email. |
| SECOPS_SIEM_CLIENT_ID | `string` | ✅ | string |  | Service account client ID. |
| SECOPS_SIEM_CLIENT_CERT_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Client x509 certificate URL. |
| CONNECTOR_NAME | `string` |  | string | `"GoogleSecOpsSIEM"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["google-secops-siem"]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| SECOPS_SIEM_PROJECT_REGION | `string` |  | string | `"us"` | Google SecOps SIEM project region (e.g. 'us', 'eu', 'apac'). |
| SECOPS_SIEM_AUTH_URI | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://accounts.google.com/o/oauth2/auth"` | OAuth2 authorization URI. |
| SECOPS_SIEM_TOKEN_URI | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://oauth2.googleapis.com/token"` | OAuth2 token URI. |
| SECOPS_SIEM_AUTH_PROVIDER_CERT | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://www.googleapis.com/oauth2/v1/certs"` | Auth provider x509 certificate URL. |
