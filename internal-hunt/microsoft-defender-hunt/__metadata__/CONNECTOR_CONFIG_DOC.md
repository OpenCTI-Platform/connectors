# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| MICROSOFT_DEFENDER_HUNT_TENANT_ID | `string` | ✅ | string |  | Microsoft Entra tenant ID of the app registration. |
| MICROSOFT_DEFENDER_HUNT_CLIENT_ID | `string` | ✅ | string |  | Client (application) ID of the app registration. |
| MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Client secret of the app registration. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Defender Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["microsoft-defender"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"Microsoft Defender XDR"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"XDR"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| MICROSOFT_DEFENDER_HUNT_LOGIN_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://login.microsoftonline.com/"` | Microsoft Entra ID login URL: 'https://login.microsoftonline.com' (global and US Government L4) or 'https://login.microsoftonline.us' (US Government L5, DoD). |
| MICROSOFT_DEFENDER_HUNT_GRAPH_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://graph.microsoft.com/"` | Microsoft Graph URL: 'https://graph.microsoft.com' (global), 'https://graph.microsoft.us' (US Government L4) or 'https://dod-graph.microsoft.us' (US Government L5, DoD). |
| MICROSOFT_DEFENDER_HUNT_SIGMA_PIPELINE | `string` |  | string | `"microsoft_xdr"` | pySigma pipeline translating Sigma rules: 'microsoft_xdr' (Defender XDR advanced hunting tables) or 'none'. |
