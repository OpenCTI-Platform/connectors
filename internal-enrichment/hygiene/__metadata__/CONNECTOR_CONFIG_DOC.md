# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"Hygiene"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Artifact", "Domain-Name", "StixFile", "Indicator"]` | The scope defines the set of entity types that the enrichment connector is allowed to process. |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | Enables or disables automatic enrichment of observables for OpenCTI. |
| HYGIENE_WARNINGLISTS_SLOW_SEARCH | `boolean` |  | boolean | `false` | Enable slow search mode for the warning lists. If true, uses the most appropriate search method. Can be slower. Default: exact match. |
| HYGIENE_LABEL_NAME | `string` |  | string | `"hygiene"` | Set the label name. |
| HYGIENE_LABEL_COLOR | `string` |  | string | `"#fc0341"` | Color to use for the label. |
| HYGIENE_LABEL_PARENT_NAME | `string` |  | string | `"hygiene_parent"` | Label name to be used when enriching sub-domains. |
| HYGIENE_LABEL_PARENT_COLOR | `string` |  | string | `"#fc0341"` | Color to use for the label when enriching subdomains. |
| HYGIENE_ENRICH_SUBDOMAINS | `boolean` |  | boolean | `false` | Enable enrichment of sub-domains, This option will add 'hygiene_parent' label and ext refs of the parent domain to the subdomain, if sub-domain is not found but parent is. |
| HYGIENE_MAX_WORKERS | `integer` |  | `1 <= x <= 500` | `100` | Maximum number of worker threads for parallel processing. Set to 1 for sequential processing (old behavior). |
