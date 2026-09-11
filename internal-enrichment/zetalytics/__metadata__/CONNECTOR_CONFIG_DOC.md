# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ZETALYTICS_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Zetalytics API token. |
| CONNECTOR_ID | `string` |  | string | `"00000000-0000-4000-8000-000000000101"` | A UUID v4 identifying this connector instance in OpenCTI. Must be overridden with a unique value per deployed profile. |
| CONNECTOR_NAME | `string` |  | string | `"Zetalytics DNS - Analyst Enrichment"` | Display name for this connector in OpenCTI. The configured ZETALYTICS_LOOKBACK_DAYS is automatically appended, e.g. `Zetalytics DNS - Deep Investigation (2 years)`. |
| CONNECTOR_SCOPE | `array` |  | string | `["Domain-Name", "Hostname", "IPv4-Addr", "IPv6-Addr"]` | Observable types this connector will enrich. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| ZETALYTICS_REQUEST_TIMEOUT | `integer` |  | integer | `30` | HTTP request timeout in seconds for all Zetalytics API calls. |
| ZETALYTICS_MODE | `string` |  | `light` `playbook` `manual` `deep` | `"manual"` | Enrichment profile controlling which endpoints are called by default. Endpoint flags below override mode defaults. |
| ZETALYTICS_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP level of observables this connector will enrich. |
| ZETALYTICS_MAX_RESULTS | `integer` |  | integer | `300` | Maximum passive DNS records to retrieve per query. |
| ZETALYTICS_MAX_SUBDOMAINS | `integer` |  | integer | `300` | Maximum subdomains to retrieve. |
| ZETALYTICS_MAX_WHOIS_RESULTS | `integer` |  | integer | `5` | Maximum historical WHOIS records to retrieve. |
| ZETALYTICS_MAX_NS_PIVOT_RESULTS | `integer` |  | integer | `100` | Maximum results for nameserver pivot queries. |
| ZETALYTICS_LOOKBACK_DAYS | `integer` |  | integer | `365` | How many days back to query passive DNS records. |
| ZETALYTICS_TSFIELD | `string` |  | `all` `last_seen` `first_seen` | `"all"` | Zetalytics timestamp field to filter on. |
| ZETALYTICS_INCLUDE_LIVE_DNS | `boolean` |  | boolean | `true` | Perform a live DNS lookup in addition to passive DNS. |
| ZETALYTICS_INCLUDE_SUBDOMAINS | `boolean` |  | boolean | `true` | Retrieve known subdomains for domain enrichment. |
| ZETALYTICS_INCLUDE_D8S | `boolean` |  | boolean | `true` | Retrieve structured D8S registration context for domains. |
| ZETALYTICS_INCLUDE_HISTORICAL_WHOIS | `boolean` |  | boolean | `false` | Retrieve historical raw WHOIS data (disabled by default due to volume). |
| ZETALYTICS_INCLUDE_NS_GLUE | `boolean` |  | boolean | `true` | Retrieve nameserver glue records. |
| ZETALYTICS_INCLUDE_NS2DOMAIN | `boolean` |  | boolean | `false` | Pivot from nameserver to hosted domains (deep mode only). |
| ZETALYTICS_INCLUDE_MX2DOMAIN | `boolean` |  | boolean | `false` | Pivot from MX domain to hosted domains (deep mode only). |
| ZETALYTICS_INCLUDE_EMAIL_PIVOTS | `boolean` |  | boolean | `false` | Enrich via registration email pivots (disabled by default). |
| ZETALYTICS_CONFIDENCE | `integer` |  | integer, 0-100 | `60` | Confidence score applied to created STIX objects. |
| ZETALYTICS_MARKING_DEFINITION | `string` |  | string | `"TLP:AMBER"` | TLP marking definition to apply to created objects. |
| ZETALYTICS_CREATE_NOTE_WHEN_NO_RESULTS | `boolean` |  | boolean | `false` | Create an OpenCTI note on the observable when no results are found. |
| ZETALYTICS_INCLUDE_PORTAL_LINK | `boolean` |  | boolean | `true` | Add an external reference linking to the observable in the ZoneCruncher web portal. The link includes the API token as part of the URL path, which is visible to OpenCTI users who can view the observable. Set to false to omit. |
