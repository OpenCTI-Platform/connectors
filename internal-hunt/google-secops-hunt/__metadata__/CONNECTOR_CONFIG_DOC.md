# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| GOOGLE_SECOPS_HUNT_PROJECT_ID | `string` | ✅ | string |  | Google Cloud project ID of the SecOps instance. |
| GOOGLE_SECOPS_HUNT_PROJECT_REGION | `string` | ✅ | string |  | Region of the SecOps instance, e.g. 'us', 'europe' or 'asia-southeast1'. |
| GOOGLE_SECOPS_HUNT_PROJECT_INSTANCE | `string` | ✅ | string |  | Customer ID (instance UUID) of SecOps. |
| GOOGLE_SECOPS_HUNT_PRIVATE_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Service account private key (PEM). |
| GOOGLE_SECOPS_HUNT_PRIVATE_KEY_ID | `string` | ✅ | string |  | Service account private key ID. |
| GOOGLE_SECOPS_HUNT_CLIENT_EMAIL | `string` | ✅ | string |  | Service account client email. |
| GOOGLE_SECOPS_HUNT_CLIENT_ID | `string` | ✅ | string |  | Service account client ID. |
| CONNECTOR_NAME | `string` |  | string | `"Google SecOps Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["google-secops"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"Google SecOps"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| GOOGLE_SECOPS_HUNT_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://chronicle.googleapis.com/"` | Chronicle API URL; the region is prefixed to the host at runtime. |
| GOOGLE_SECOPS_HUNT_AUTH_URI | `string` |  | string | `"https://accounts.google.com/o/oauth2/auth"` | OAuth2 auth URI of the service account. |
| GOOGLE_SECOPS_HUNT_TOKEN_URI | `string` |  | string | `"https://oauth2.googleapis.com/token"` | OAuth2 token URI of the service account. |
| GOOGLE_SECOPS_HUNT_AUTH_PROVIDER_CERT | `string` |  | string | `"https://www.googleapis.com/oauth2/v1/certs"` | OAuth2 auth provider certificates URL of the service account. |
| GOOGLE_SECOPS_HUNT_CLIENT_CERT_URL | `string` |  | string | `""` | Client certificate URL of the service account. |
| GOOGLE_SECOPS_HUNT_QUERY_LANGUAGE | `string` |  | `udm` `yara-l` | `"udm"` | Language Sigma rules are translated into: 'udm' (UDM search, returns the matching events) or 'yara-l' (YARA-L 2.0 rule tested over the run window, returns detections). |
| GOOGLE_SECOPS_HUNT_SIGMA_PIPELINE | `string` |  | string | `"secops_udm"` | pySigma pipeline(s) translating Sigma rules, chained with '+': 'secops_udm' or 'none'. |
