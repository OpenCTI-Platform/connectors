# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SPLUNK_SAVED_SEARCHES_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of the Splunk REST API (management port), e.g. `https://splunk.example.com:8089`. |
| SPLUNK_SAVED_SEARCHES_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Splunk authentication token, sent as `Authorization: Bearer <token>`. Its user needs read access to the saved searches of the selected apps. |
| CONNECTOR_NAME | `string` |  | string | `"Splunk Saved Searches"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Attack-Pattern", "SecurityPlatform"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). Every run reads the full rule set. |
| SPLUNK_SAVED_SEARCHES_APP | `string` |  | Length: `string >= 1` | `"-"` | App namespace to read saved searches from. `-` reads every app. |
| SPLUNK_SAVED_SEARCHES_OWNER | `string` |  | Length: `string >= 1` | `"-"` | Owner namespace to read saved searches from. `-` reads every owner. |
| SPLUNK_SAVED_SEARCHES_SEARCH_SCOPE | `string` |  | `correlation_searches` `alerts` `all` | `"alerts"` | Saved searches to import: `correlation_searches` (Enterprise Security correlation searches only), `alerts` (correlation searches, scheduled searches that trigger alert actions, and saved searches annotated with ATT&CK techniques in `action.correlationsearch.annotations`) or `all`. |
| SPLUNK_SAVED_SEARCHES_WEB_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Base URL of Splunk Web, e.g. `https://splunk.example.com:8000`. When set, each Indicator links to its saved search. |
| SPLUNK_SAVED_SEARCHES_IMPORT_DISABLED_RULES | `boolean` |  | boolean | `true` | Import saved searches that do not run (disabled or not scheduled) too, with the deployment status `deployed` (enabled and scheduled ones get `active`). When false, they are left out and count as removed. |
| SPLUNK_SAVED_SEARCHES_PAGE_SIZE | `integer` |  | `1 <= x <= 10000` | `100` | Saved searches requested per page (`count`). |
| SPLUNK_SAVED_SEARCHES_REQUEST_TIMEOUT | `integer` |  | `1 <= x ` | `60` | Timeout of each HTTP request, in seconds. |
| SPLUNK_SAVED_SEARCHES_MAX_RETRIES | `integer` |  | `0 <= x ` | `5` | Retries of a request failing with a rate limit (429), a server error (5xx) or a network error, with exponential backoff. |
| SPLUNK_SAVED_SEARCHES_VERIFY_SSL | `boolean` |  | boolean | `true` | Verify the TLS certificate of the Splunk REST API. |
| SPLUNK_SAVED_SEARCHES_PLATFORM_NAME | `string` |  | Length: `string >= 1` | `"Splunk"` | Name of the Security Platform the rules are deployed on in OpenCTI. |
| SPLUNK_SAVED_SEARCHES_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of that Security Platform (`security_platform_type`). |
| SPLUNK_SAVED_SEARCHES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
