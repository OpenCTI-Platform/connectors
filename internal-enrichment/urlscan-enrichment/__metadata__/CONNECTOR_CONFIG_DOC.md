# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Urlscan Enrichment"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["url", "ipv4-addr", "ipv6-addr"]` | The scope of the connector. Availables: `url or hostname or domain-name` (scope-submission), `ipv4-addr` and `ipv6-addr` (scope-search) |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| URLSCAN_ENRICHMENT_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | URLScan API Key |
| URLSCAN_ENRICHMENT_IMPORT_SCREENSHOT | `boolean` |  | boolean | `true` | Allows or not the import of the screenshot of the scan submitted in URLScan to OpenCTI. |
| URLSCAN_ENRICHMENT_VISIBILITY | `string` |  | `public` `unlisted` `private` | `"public"` | URLScan offers several levels of visibility for submitted scans: `public`, `unlisted`, `private` |
| URLSCAN_ENRICHMENT_SEARCH_FILTERED_BY_DATE | `string` |  | string | `">now-1y"` | Allows you to filter by date available: `>now-1h`, `>now-1d`, `>now-1y`, `[2022 TO 2023]`, `[2022/01/01 TO 2023/12/01]` |
| URLSCAN_ENRICHMENT_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Do not send any data to URLScan if the TLP of the observable is greater than MAX_TLP |
| URLSCAN_ENRICHMENT_CREATE_INDICATOR | `boolean` |  | boolean | `true` | Decide whether or not to create an indicator based on this observable |
