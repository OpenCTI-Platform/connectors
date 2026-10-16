# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SENTINELONE_HUNT_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | URL of the SentinelOne management console of your tenant, e.g. 'https://your-tenant.sentinelone.net'. |
| SENTINELONE_HUNT_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token of a SentinelOne service user with a read-only role that can search events (e.g. Viewer) on the accounts or sites to hunt. |
| CONNECTOR_NAME | `string` |  | string | `"SentinelOne Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["sentinelone"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"SentinelOne Singularity"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"EDR"` | Type of the OpenCTI Security Platform the hunts are executed against ('XDR' when the Singularity Data Lake also holds third-party data you hunt). |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `3` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time (a run holds one query on the platform at a time). The platform budget is the minimum of its own setting and this value. Defaults to 3: SentinelOne throttles query launches and does not document the concurrent query budget of an account. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| SENTINELONE_HUNT_ACCOUNT_IDS | `array` |  | string | `[]` | Account IDs the hunts search, comma-separated. Empty searches every account the token can reach. |
| SENTINELONE_HUNT_EDR_ONLY | `boolean` |  | boolean | `true` | Restrict translated Sigma rules and indicator lookups to the SentinelOne EDR telemetry (dataSource.name='SentinelOne' dataSource.category='security') and check their field names against the EDR schema, so that a misspelled field fails the run instead of matching nothing. Set to false to also search the third-party data of the Singularity Data Lake. |
| SENTINELONE_HUNT_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TLS certificate of the console. |
| SENTINELONE_HUNT_SIGMA_PIPELINE | `string` |  | string | `"sentinelone_pq"` | pySigma pipeline translating Sigma rules: 'sentinelone_pq' (the field mapping of the SentinelOne EDR telemetry) or 'none' (rules already written with SentinelOne field names). |
| SENTINELONE_HUNT_POLL_INTERVAL | `number` |  | `0 < x <= 10` | `1.0` | Seconds between two status checks of a query. SentinelOne drops a query that is not polled for 30 seconds. |
