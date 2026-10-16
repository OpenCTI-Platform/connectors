# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CYMRU_SCOUT_HUNT_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Team Cymru Scout API key of an account with search queries. |
| CONNECTOR_NAME | `string` |  | string | `"Team Cymru Scout Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["cymru-scout"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `null` | Name of the OpenCTI Security Platform the hunts are executed against (created when missing). Leave empty only for the internet scanning platforms: censys, silentpush, urlscan, cymru-scout, shodan. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `1` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time (a run sends one search at a time). The platform budget is the minimum of its own setting and this value. Defaults to 1: Team Cymru Scout answers 1 request per second and caps the concurrent requests of an account. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| CYMRU_SCOUT_HUNT_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://scout.cymru.com/api/scout"` | URL of the Team Cymru Scout API. |
