# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdStrike LogScale Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crowdstrike-logscale"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"CrowdStrike Falcon"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT | `string` |  | `falcon` `logscale` | `"falcon"` | 'falcon' queries Falcon Next-Gen SIEM through the CrowdStrike API (OAuth2 client credentials); 'logscale' queries a LogScale cluster (self-hosted or LogScale Cloud) with an API token. |
| CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.crowdstrike.com/"` | CrowdStrike API URL of the Falcon cloud: 'https://api.crowdstrike.com' (US-1), 'https://api.us-2.crowdstrike.com', 'https://api.eu-1.crowdstrike.com' or 'https://api.laggar.gcw.crowdstrike.com' (GOV). |
| CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID | `string` |  | string | `null` | CrowdStrike API client ID (deployment 'falcon'). |
| CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | CrowdStrike API client secret (deployment 'falcon'). |
| CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | URL of the LogScale cluster, e.g. 'https://cloud.us.humio.com' (deployment 'logscale'). |
| CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | LogScale API token with the search permission on the repository (deployment 'logscale'). |
| CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY | `string` |  | string | `"search-all"` | Repository or view the hunts search: 'search-all' (all Falcon and third-party data), 'investigate_view', 'third-party', or a LogScale repository name. |
| CROWDSTRIKE_LOGSCALE_HUNT_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TLS certificate of the API. |
| CROWDSTRIKE_LOGSCALE_HUNT_SIGMA_PIPELINE | `string` |  | string | `"crowdstrike_falcon"` | pySigma pipeline(s) translating Sigma rules, chained with '+': 'crowdstrike_falcon' (Falcon telemetry), 'crowdstrike_fdr' (Falcon Data Replicator events) or 'none'. |
| CROWDSTRIKE_LOGSCALE_HUNT_POLL_INTERVAL | `number` |  | `0 < x ` | `1.0` | Seconds between two status checks of a query job, when LogScale gives no hint. |
