# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ELASTIC_DETECTION_RULES_KIBANA_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Base URL of Kibana, without the space prefix (e.g. `https://kibana.example.com:5601`). |
| ELASTIC_DETECTION_RULES_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Encoded Elasticsearch API key (the base64 `id:api_key` value), sent as `Authorization: ApiKey <key>`. It needs the Kibana privilege `Security > Rules and Exceptions: Read` in the space. |
| CONNECTOR_NAME | `string` |  | string | `"Elastic Security Detection Rules"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Attack-Pattern", "SecurityPlatform"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). Every run reads the full rule set. |
| ELASTIC_DETECTION_RULES_SPACE_ID | `string` |  | string | `null` | Kibana space holding the rules. Leave empty for the default space. |
| ELASTIC_DETECTION_RULES_RULE_FILTER | `string` |  | string | `null` | Optional KQL filter on rule attributes passed to the detection engine `_find` API (e.g. `alert.attributes.tags:"Production"`). |
| ELASTIC_DETECTION_RULES_IMPORT_DISABLED_RULES | `boolean` |  | boolean | `true` | Import disabled rules too, with the deployment status `deployed` (enabled rules get `active`). When false, disabled rules are left out and count as removed. |
| ELASTIC_DETECTION_RULES_PAGE_SIZE | `integer` |  | `1 <= x <= 1000` | `100` | Rules requested per page of the `_find` API. |
| ELASTIC_DETECTION_RULES_REQUEST_TIMEOUT | `integer` |  | `1 <= x ` | `60` | Timeout of each HTTP request, in seconds. |
| ELASTIC_DETECTION_RULES_MAX_RETRIES | `integer` |  | `0 <= x ` | `5` | Retries of a request failing with a rate limit (429), a server error (5xx) or a network error, with exponential backoff. |
| ELASTIC_DETECTION_RULES_VERIFY_SSL | `boolean` |  | boolean | `true` | Verify the TLS certificate of Kibana. |
| ELASTIC_DETECTION_RULES_PLATFORM_NAME | `string` |  | Length: `string >= 1` | `"Elastic Security"` | Name of the Security Platform the rules are deployed on in OpenCTI. |
| ELASTIC_DETECTION_RULES_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of that Security Platform (`security_platform_type`). |
| ELASTIC_DETECTION_RULES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
