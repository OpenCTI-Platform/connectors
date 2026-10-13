# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'indicator, vulnerability'. |
| STAIRWELL_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Stairwell API token (Bearer auth). |
| CONNECTOR_NAME | `string` |  | string | `"Stairwell Import"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | Interval between two runs of the connector (ISO-8601). |
| STAIRWELL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://app.stairwell.com"` | Stairwell API base URL. |
| STAIRWELL_ORGANIZATION_ID | `string` |  | string | `""` | Optional Stairwell organization id (rate-limit header). |
| STAIRWELL_USER_ID | `string` |  | string | `""` | Optional Stairwell user id (rate-limit header). |
| STAIRWELL_IMPORT_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"green"` | TLP marking applied to imported entities. |
| STAIRWELL_IMPORT_FIRST_RUN_WINDOW | `string` |  | string | `"P1D"` | ISO-8601 duration to backfill on the first run. |
| STAIRWELL_IMPORT_MAX_INDICATORS | `integer` |  | integer | `1000` | Maximum indicators emitted per run. |
| STAIRWELL_IMPORT_PAGE_SIZE | `integer` |  | integer | `100` | Stairwell API page size. |
| STAIRWELL_IMPORT_INDICATOR_VALIDITY_DAYS | `integer` |  | integer | `90` | Days added to valid_from to compute valid_until. |
| STAIRWELL_IMPORT_MIN_BUCKET | `string` |  | string | `"HIGH"` | Minimum MalEval bucket: LOW, MEDIUM, HIGH, or VERY_HIGH. |
| STAIRWELL_IMPORT_SCOPE | `string` |  | string | `"environment"` | Reserved (forward-compat): accepted but not yet effective; every run currently queries the full corpus regardless of this value. |
| STAIRWELL_IMPORT_WRAPPER | `string` |  | `grouping` `report` | `"grouping"` | Per-run wrapper SDO: 'grouping' or 'report'. |
