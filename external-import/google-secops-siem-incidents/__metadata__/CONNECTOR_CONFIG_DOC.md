# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_ID | `string` | ✅ | string |  | GCP project ID. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_REGION | `string` | ✅ | string |  | Region (e.g. 'us', 'eu', 'asia'). |
| GOOGLE_SECOPS_SIEM_INCIDENTS_PROJECT_INSTANCE | `string` | ✅ | string |  | Instance UUID. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY | `string` | ✅ | string |  | Service account private key (PEM). |
| GOOGLE_SECOPS_SIEM_INCIDENTS_PRIVATE_KEY_ID | `string` | ✅ | string |  | Service account private key ID. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_EMAIL | `string` | ✅ | string |  | Service account client email. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_ID | `string` | ✅ | string |  | Service account client ID. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_CLIENT_CERT_URL | `string` | ✅ | string |  | Service account client cert URL. |
| CONNECTOR_NAME | `string` |  | string | `"Google SecOps"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["google-secops-siem-incidents"]` | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_BASE_URL | `string` |  | string | `"https://chronicle.googleapis.com"` | API base URL (region prefix added at runtime). |
| GOOGLE_SECOPS_SIEM_INCIDENTS_AUTH_URI | `string` |  | string | `"https://accounts.google.com/o/oauth2/auth"` | OAuth2 auth URI. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_TOKEN_URI | `string` |  | string | `"https://oauth2.googleapis.com/token"` | OAuth2 token URI. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_AUTH_PROVIDER_CERT | `string` |  | string | `"https://www.googleapis.com/oauth2/v1/certs"` | OAuth2 auth provider cert URL. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | Default TLP level of the imported entities. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_FIRST_START_TIME | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | How far back to fetch alerts on the very first run (ISO-8601 duration, e.g. P1D). Used only when no prior state exists. |
| GOOGLE_SECOPS_SIEM_INCIDENTS_SEVERITY_FILTER | `string` |  | `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` | `null` | Minimum severity level to import. All alerts at or above this level are imported (critical > high > medium > low > info). When not set, all severities are imported. |
