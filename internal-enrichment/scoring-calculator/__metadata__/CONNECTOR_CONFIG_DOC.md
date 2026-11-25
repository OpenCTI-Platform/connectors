# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Scoring calculator"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| CONNECTOR_SCORING_HIGH_PRIORITY_LABELS | `string` |  | string | `"[]"` | JSON array of labels marking an entity as high priority, e.g. ["[Scoring] High priority"]. |
| CONNECTOR_SCORING_MEDIUM_PRIORITY_LABELS | `string` |  | string | `"[]"` | JSON array of labels marking an entity as medium priority, e.g. ["[Scoring] Medium priority"]. |
| CONNECTOR_SCORING_LOW_PRIORITY_LABELS | `string` |  | string | `"[]"` | JSON array of labels marking an entity as low priority, e.g. ["[Scoring] Low priority"]. |
| CONNECTOR_SCORING_INDICATOR_TYPE_ENRICHABLE | `array` |  | string | `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "StixFile"]` | Main observable types of the Indicators to enrich. |
| CONNECTOR_SCORING_BROWSE_REPORT | `boolean` |  | boolean | `false` | Whether to take into account the entities contained in the Reports containing the Indicator. |
| CONNECTOR_SCORING_THREAT_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the related threats (Intrusion Sets, Threat Actors) impact the score. |
| CONNECTOR_SCORING_THREAT_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a threat categorized as high priority. |
| CONNECTOR_SCORING_THREAT_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a threat categorized as medium priority. |
| CONNECTOR_SCORING_THREAT_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a threat categorized as low priority. |
| CONNECTOR_SCORING_TOOLBOX_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the related toolbox (Malware, Tools) impacts the score. |
| CONNECTOR_SCORING_TOOLBOX_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a toolbox categorized as high priority. |
| CONNECTOR_SCORING_TOOLBOX_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a toolbox categorized as medium priority. |
| CONNECTOR_SCORING_TOOLBOX_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a toolbox categorized as low priority. |
| CONNECTOR_SCORING_LOCATION_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the related locations (Countries, Regions) impact the score. |
| CONNECTOR_SCORING_LOCATION_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a location categorized as high priority. |
| CONNECTOR_SCORING_LOCATION_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a location categorized as medium priority. |
| CONNECTOR_SCORING_LOCATION_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a location categorized as low priority. |
| CONNECTOR_SCORING_SECTOR_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the related sectors impact the score. |
| CONNECTOR_SCORING_SECTOR_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a sector categorized as high priority. |
| CONNECTOR_SCORING_SECTOR_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a sector categorized as medium priority. |
| CONNECTOR_SCORING_SECTOR_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a sector categorized as low priority. |
| CONNECTOR_SCORING_TTP_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the related TTPs (Attack Patterns) impact the score. |
| CONNECTOR_SCORING_TTP_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a TTP categorized as high priority. |
| CONNECTOR_SCORING_TTP_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a TTP categorized as medium priority. |
| CONNECTOR_SCORING_TTP_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of a TTP categorized as low priority. |
| CONNECTOR_SCORING_AUTHOR_IMPACT_SCORE | `boolean` |  | boolean | `false` | Whether the author (Organization) impacts the score. |
| CONNECTOR_SCORING_AUTHOR_HIGH_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of an author categorized as high priority. |
| CONNECTOR_SCORING_AUTHOR_MEDIUM_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of an author categorized as medium priority. |
| CONNECTOR_SCORING_AUTHOR_LOW_PRIORITY | `integer` |  | integer | `0` | Impact (%) on the score of an author categorized as low priority. |
