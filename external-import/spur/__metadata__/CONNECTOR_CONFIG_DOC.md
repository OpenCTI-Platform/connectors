# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |
| SPUR_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Spur API token. |
| CONNECTOR_NAME | `string` |  | string | `"Spur"` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | Interval between feed runs (ISO-8601). |
| SPUR_FEED_URLS | `array` |  | string | `["https://feeds.spur.us/v2/anonymous/feed.json.gz", "https://feeds.spur.us/v2/residential/feed.json.gz"]` | Comma-separated list of Spur feed URLs to download. |
| SPUR_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to all imported objects. |
| SPUR_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Create STIX Indicators for flagged IPs. |
| SPUR_CREATE_ASNS | `boolean` |  | boolean | `true` | Create AutonomousSystem objects and belongs-to relationships. |
| SPUR_CREATE_LOCATIONS | `boolean` |  | boolean | `true` | Create Location objects and located-at relationships. |
| SPUR_DEFAULT_SCORE | `integer` |  | `0 <= x <= 100` | `70` | Base OpenCTI score for Spur observables (0-100). |
| SPUR_BATCH_SIZE | `integer` |  | `100 <= x ` | `5000` | Number of IP records per STIX bundle sent to OpenCTI. |
