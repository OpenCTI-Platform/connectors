# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| STAIRWELL_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Stairwell API token (Bearer auth). |
| CONNECTOR_NAME | `string` |  | string | `"Stairwell"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile", "Domain-Name", "IPv4-Addr", "IPv6-Addr", "Autonomous-System"]` | The observable types the connector enriches. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| STAIRWELL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://app.stairwell.com"` | Stairwell API base URL. |
| STAIRWELL_ORGANIZATION_ID | `string` |  | string | `""` | Optional Stairwell organization id (rate-limit header). |
| STAIRWELL_USER_ID | `string` |  | string | `""` | Optional Stairwell user id (rate-limit header). |
| STAIRWELL_DEFAULT_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to entities created by enrichment. |
| STAIRWELL_VARIANT_LIMIT | `integer` |  | integer | `25` | Max variant SCOs per file enrichment (0 disables). |
| STAIRWELL_RESOLUTIONS_LIMIT | `integer` |  | integer | `50` | Max DNS resolution rows per domain (0 disables). |
| STAIRWELL_SIGHTINGS_LIMIT | `integer` |  | integer | `0` | Max unique assets per file; 0 (the default) disables sightings. Enabling writes asset names, environment ids, and file paths into OpenCTI. |
