# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Infrastructure Tracker"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["internet"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `null` | Name of the OpenCTI Security Platform the hunts are executed against (created when missing). Leave empty only for the 'internet' platform. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| INFRASTRUCTURE_TRACKER_CENSYS_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Censys Platform personal access token. Leave empty to disable Censys. |
| INFRASTRUCTURE_TRACKER_CENSYS_ORGANISATION_ID | `string` |  | string | `null` | Censys organization ID (required by paid Censys Platform accounts). |
| INFRASTRUCTURE_TRACKER_CENSYS_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.platform.censys.io/"` | URL of the Censys Platform API. |
| INFRASTRUCTURE_TRACKER_SILENTPUSH_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Silent Push API key. Leave empty to disable Silent Push. |
| INFRASTRUCTURE_TRACKER_SILENTPUSH_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.silentpush.com/"` | URL of the Silent Push API. |
| INFRASTRUCTURE_TRACKER_URLSCAN_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | urlscan.io API key. Leave empty to disable urlscan.io. |
| INFRASTRUCTURE_TRACKER_URLSCAN_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://urlscan.io/"` | URL of the urlscan.io API. |
| INFRASTRUCTURE_TRACKER_CYMRU_SCOUT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Team Cymru Scout API key. Leave empty to disable Team Cymru Scout. |
| INFRASTRUCTURE_TRACKER_CYMRU_SCOUT_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://scout.cymru.com/api/scout"` | URL of the Team Cymru Scout API. |
| INFRASTRUCTURE_TRACKER_INTERNETDB_ENABLED | `boolean` |  | boolean | `true` | Whether to enrich the IP addresses found with Shodan InternetDB (host names, ports, tags; no API key needed). |
| INFRASTRUCTURE_TRACKER_INTERNETDB_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://internetdb.shodan.io/"` | URL of Shodan InternetDB. |
| INFRASTRUCTURE_TRACKER_INTERNETDB_MAX_LOOKUPS | `integer` |  | `0 <= x <= 1000` | `25` | Maximum number of IP addresses enriched with Shodan InternetDB per hunt run. |
| INFRASTRUCTURE_TRACKER_CREATE_CERTIFICATES | `boolean` |  | boolean | `true` | Whether to create the X.509 certificates found (with their indicators). |
