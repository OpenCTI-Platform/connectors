# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| MISP_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the MISP instance. |
| MISP_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | MISP automation API key. |
| CONNECTOR_NAME | `string` |  | string | `"MISP Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "Email-Addr", "Indicator"]` | The OpenCTI entity types the connector enriches. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| MISP_SSL_VERIFY | `boolean` |  | boolean | `true` | Verify the SSL certificate of the MISP instance. |
| MISP_IMPORT_ATTRIBUTE_TAGS_AS_LABELS | `boolean` |  | boolean | `true` | Apply the tags of the matched MISP attributes as labels on the enriched entity. |
| MISP_IMPORT_ASSOCIATED_EVENTS_TAGS_AS_LABELS | `boolean` |  | boolean | `false` | Apply the tags of the matched MISP events as labels on the enriched entity. |
| MISP_EVENT_FILTER_CREATOR_ORGS | `array` |  | string | `[]` | Creator organisations (Event.Orgc, name or UUID) to include. If set, only events created by one of these organisations are considered. |
| MISP_EVENT_FILTER_CREATOR_ORGS_NOT | `array` |  | string | `[]` | Creator organisations (Event.Orgc, name or UUID) to exclude. |
| MISP_EVENT_FILTER_OWNER_ORGS | `array` |  | string | `[]` | Owner organisations (Event.Org, name or UUID) to include. If set, only events owned by one of these organisations are considered. |
| MISP_EVENT_FILTER_OWNER_ORGS_NOT | `array` |  | string | `[]` | Owner organisations (Event.Org, name or UUID) to exclude. |
| MISP_EVENT_FILTER_NAME_REGEX | `string` |  | string | `null` | Regex searched in the event name (Event.info). Only events whose name matches are considered. |
| MISP_ATTRIBUTE_COMMENT_FILTER_REGEX | `string` |  | string | `null` | Regex searched in the attribute comment. The comment of a matched attribute is written in the Note only if it matches. |
| MISP_IMPORT_EVENTS | `boolean` |  | boolean | `false` | Create one OpenCTI Report per matched MISP event, containing the enriched entity. |
