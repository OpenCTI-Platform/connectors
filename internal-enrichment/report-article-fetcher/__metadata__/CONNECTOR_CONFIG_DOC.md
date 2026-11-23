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
| REPORT_ARTICLE_FETCHER_FOLLOW_PDF | `boolean` |  | boolean | `true` | On a landing page (a short page that links its report as a PDF on the same site), also fetch the PDF: its text follows the page in the report's content and the file is attached to the report. |
| REPORT_ARTICLE_FETCHER_LANDING_MAX_LENGTH | `integer` |  | `0 <= x ` | `4000` | A page whose extracted text is shorter than this, in characters, is a landing page whose linked PDF report is followed. |
| REPORT_ARTICLE_FETCHER_MAX_PDF_SIZE | `integer` |  | `0 < x ` | `20000000` | Largest PDF report downloaded from a landing page, in bytes. |
| REPORT_ARTICLE_FETCHER_MATCH_SINGLE_REFERENCE | `boolean` |  | boolean | `false` | Also accept reports not created by the RSS ingestion when they have exactly one external reference. |
| REPORT_ARTICLE_FETCHER_MAX_WORKERS | `integer` |  | `1 <= x <= 32` | `1` | Reports processed at the same time by one connector process. Each worker consumes the queue with its own OpenCTI client and HTTP session, like a replica of the connector. Requires the AMQP listen protocol. |
| REPORT_ARTICLE_FETCHER_SUMMARY_LOG_LEVEL | `string` |  | `debug` `info` `warning` `error` `none` | `"error"` | Level of the one-line summary written for each report (outcome, skip reason, fetch, extraction, check and send times). The default is visible under the default log level; none turns it off. |
