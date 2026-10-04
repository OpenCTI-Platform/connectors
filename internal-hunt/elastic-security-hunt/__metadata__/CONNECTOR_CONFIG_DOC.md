# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ELASTIC_SECURITY_HUNT_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | URL of the Elasticsearch cluster, e.g. 'https://elastic.example.com:9200'. |
| CONNECTOR_NAME | `string` |  | string | `"Elastic Security Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["elastic-security"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"Elastic Security"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| ELASTIC_SECURITY_HUNT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Elasticsearch API key, encoded (the base64 'id:api_key' value). Leave empty to use username and password. |
| ELASTIC_SECURITY_HUNT_USERNAME | `string` |  | string | `null` | Elasticsearch user name, used when no API key is set. |
| ELASTIC_SECURITY_HUNT_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Elasticsearch user password, used when no API key is set. |
| ELASTIC_SECURITY_HUNT_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TLS certificate of the cluster. |
| ELASTIC_SECURITY_HUNT_CA_CERT | `string` |  | string | `null` | Path to a CA certificate bundle verifying the cluster certificate. |
| ELASTIC_SECURITY_HUNT_INDICES | `array` |  | string | `["logs-*", "winlogbeat-*", "filebeat-*", "auditbeat-*", "endgame-*"]` | Index patterns the hunts search (EQL and Lucene queries, and the ES|QL queries translated from Sigma rules). |
| ELASTIC_SECURITY_HUNT_QUERY_LANGUAGE | `string` |  | `esql` `eql` `lucene` | `"esql"` | Language Sigma rules are translated into: 'esql' (ES|QL, Elasticsearch 8.13+), 'eql' or 'lucene'. |
| ELASTIC_SECURITY_HUNT_SIGMA_PIPELINE | `string` |  | string | `"ecs_windows"` | pySigma pipeline(s) translating Sigma rules, chained with '+': 'ecs_windows', 'ecs_windows_old', 'ecs_kubernetes', 'ecs_macos_esf', 'ecs_zeek_beats', 'ecs_zeek_corelight', 'zeek' or 'none'. |
| ELASTIC_SECURITY_HUNT_TIMESTAMP_FIELD | `string` |  | string | `"@timestamp"` | Field holding the event time, used to restrict the queries to the run window. |
