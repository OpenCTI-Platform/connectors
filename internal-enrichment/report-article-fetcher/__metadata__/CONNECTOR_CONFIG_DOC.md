# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Report Article Fetcher"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Report"]` | The entity types the connector enriches. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| REPORT_ARTICLE_FETCHER_USER_AGENT | `string` |  | string | `"OpenCTI Report Article Fetcher"` | User-Agent sent when fetching article pages. |
| REPORT_ARTICLE_FETCHER_REQUEST_TIMEOUT | `integer` |  | `0 < x ` | `20` | Timeout of one page request, in seconds. |
| REPORT_ARTICLE_FETCHER_MAX_DOWNLOAD_SIZE | `integer` |  | `0 < x ` | `5000000` | Largest page downloaded, in bytes. |
| REPORT_ARTICLE_FETCHER_MIN_LENGTH | `integer` |  | `0 <= x ` | `500` | Shortest extracted article accepted, in characters of text. |
| REPORT_ARTICLE_FETCHER_LENGTH_RATIO | `number` |  | `1 <= x ` | `1.5` | The article must be this many times longer than the report's current text. |
| REPORT_ARTICLE_FETCHER_MIN_TITLE_SIMILARITY | `number` |  | `0 <= x <= 1` | `0.6` | Lowest match accepted between the report name and the page (0 to 1): page title, words of the name at the top of the text, or URL slug. |
| REPORT_ARTICLE_FETCHER_MATCH_SINGLE_REFERENCE | `boolean` |  | boolean | `false` | Also accept reports not created by the RSS ingestion when they have exactly one external reference. |
