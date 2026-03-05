# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| RECORDED_FUTURE_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API Token for Recorded Future. |
| CONNECTOR_NAME | `string` |  | string | `"RecordedFutureEnrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["ipv4-addr", "ipv6-addr", "domain-name", "url", "stixfile", "vulnerability"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| RECORDED_FUTURE_CREATE_INDICATOR_THRESHOLD | `integer` |  | `0 <= x <= 100` | `0` | The risk score threshold at which an indicator will be created for enriched observables. |
| RECORDED_FUTURE_INFO_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Max TLP marking of the entity to enrich (inclusive). |
| RECORDED_FUTURE_THREAT_ACTOR_TO_INTRUSION_SET | `boolean` |  | boolean | `false` | Whether to convert Threat Actor entities to Intrusion Set entities. |
| RECORDED_FUTURE_VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS | `array` |  | string | `[]` | A list of optional fields to enrich vulnerabilities with. (For vulnerability enrichment only) |
