# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| OPENSEARCH_OCSF_HUNT_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | URL of the OpenSearch cluster, e.g. 'https://opensearch.example.com:9200'. |
| CONNECTOR_NAME | `string` |  | string | `"OpenSearch OCSF Hunt"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["opensearch"]` | The hunt platform the connector executes against. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_HUNT` | `"INTERNAL_HUNT"` |  |
| CONNECTOR_SECURITY_PLATFORM_NAME | `string` |  | string | `"OpenSearch"` | Name of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_SECURITY_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of the OpenCTI Security Platform the hunts are executed against. |
| CONNECTOR_MAX_CONCURRENT_RUNS | `integer` |  | `1 <= x ` | `null` | Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time. The platform budget is the minimum of its own setting and this value. |
| CONNECTOR_OBSERVABLE_TYPES | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr"]` | Observable types the connector may create from hunt results, intersected with the types expected by each hunt. Defaults to IOC types only; supported values: IPv4-Addr, IPv6-Addr, Domain-Name, Url, StixFile, Email-Addr, Hostname, User-Account, Mac-Addr. |
| CONNECTOR_MAX_OBSERVABLES | `integer` |  | `0 <= x ` | `100` | Maximum number of observables created per hunt run (the most frequent first). |
| OPENSEARCH_OCSF_HUNT_USERNAME | `string` |  | string | `null` | OpenSearch user name (basic authentication). Leave empty for a cluster without the security plugin. |
| OPENSEARCH_OCSF_HUNT_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | OpenSearch user password. |
| OPENSEARCH_OCSF_HUNT_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TLS certificate of the cluster. |
| OPENSEARCH_OCSF_HUNT_CA_CERT | `string` |  | string | `null` | Path to a CA certificate bundle verifying the cluster certificate. |
| OPENSEARCH_OCSF_HUNT_INDICES | `array` |  | string | `["ocsf-*"]` | Index patterns holding the OCSF events the hunts search. |
| OPENSEARCH_OCSF_HUNT_QUERY_LANGUAGE | `string` |  | `ppl` `opensearch-lucene` | `"ppl"` | Language Sigma rules are translated into: 'ppl' (Piped Processing Language) or 'opensearch-lucene' (Lucene query string). |
| OPENSEARCH_OCSF_HUNT_SIGMA_PIPELINE | `string` |  | string | `"ocsf"` | pySigma pipeline(s) translating Sigma rules, chained with '+': 'ocsf' or 'none'. |
| OPENSEARCH_OCSF_HUNT_TIMESTAMP_FIELD | `string` |  | string | `"time"` | Field holding the event time, used to restrict the queries to the run window. |
| OPENSEARCH_OCSF_HUNT_TIMESTAMP_FORMAT | `string` |  | `epoch_millis` `date` | `"epoch_millis"` | Type of the timestamp field: 'epoch_millis' (a number of milliseconds, the OCSF 'time' attribute) or 'date' (a date field such as 'time_dt'). |
