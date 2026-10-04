# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| MICROSOFT_SENTINEL_HUNT_WORKSPACE_ID | `string` | ✅ | string |  | Workspace ID (GUID) of the Log Analytics workspace of Microsoft Sentinel. |
| CONNECTOR_NAME | `string` |  | string | `"Microsoft Sentinel Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["microsoft-sentinel"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"Microsoft Sentinel"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| MICROSOFT_SENTINEL_HUNT_AUTH_TYPE | `string` |  | `app_registration` `azure_credential` | `"app_registration"` | Authentication method: 'app_registration' (default) requires tenant_id, client_id and client_secret; 'azure_credential' uses DefaultAzureCredential (managed identity, workload identity, or a local `az login` session) and ignores them. |
| MICROSOFT_SENTINEL_HUNT_TENANT_ID | `string` |  | string | `null` | Microsoft Entra tenant ID of the app registration. |
| MICROSOFT_SENTINEL_HUNT_CLIENT_ID | `string` |  | string | `null` | Client (application) ID of the app registration. |
| MICROSOFT_SENTINEL_HUNT_CLIENT_SECRET | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Client secret of the app registration. |
| MICROSOFT_SENTINEL_HUNT_ADDITIONAL_WORKSPACES | `array` |  | string | `[]` | Other Log Analytics workspaces (IDs or resource IDs) queried with the main workspace. |
| MICROSOFT_SENTINEL_HUNT_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.loganalytics.io/"` | URL of the Log Analytics query API: 'https://api.loganalytics.io' (Azure public cloud), 'https://api.loganalytics.us' (Azure Government) or 'https://api.loganalytics.azure.cn' (Azure China). |
| MICROSOFT_SENTINEL_HUNT_AUTHORITY_HOST | `string` |  | string | `"login.microsoftonline.com"` | Microsoft Entra authority host: 'login.microsoftonline.com' (Azure public cloud), 'login.microsoftonline.us' (Azure Government) or 'login.chinacloudapi.cn' (Azure China). |
| MICROSOFT_SENTINEL_HUNT_SIGMA_PIPELINE | `string` |  | string | `"sentinel_asim"` | pySigma pipeline(s) translating Sigma rules, chained with '+': 'sentinel_asim' (ASIM parsers), 'azure_monitor' (SecurityEvent and Azure Monitor tables), 'microsoft_xdr' (Defender XDR tables streamed to Sentinel) or 'none'. |
