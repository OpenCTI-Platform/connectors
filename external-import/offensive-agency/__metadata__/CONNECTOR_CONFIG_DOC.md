# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Offensive Agency"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Tool", "IPv4-Addr"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). The feed is dated by day, so a shorter period does not bring more data. |
| OFFENSIVE_AGENCY_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://www.offensive.agency/api/v1"` | Base URL of the offensive.agency API. The connector reads the STIX feed at `<api_base_url>/feeds/stix.json`. |
| OFFENSIVE_AGENCY_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object the connector creates. The feed is public and carries no marking. |
| OFFENSIVE_AGENCY_INDICATOR_VALIDITY | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | How long an indicator stays valid after the feed last saw the agent on its IP, as an ISO 8601 duration (e.g. `P30D` for 30 days). The feed only keeps the last 7 days: an IP that leaves it expires in OpenCTI once this period has passed. Minimum `P1D`, since the feed is dated by day. |
| OFFENSIVE_AGENCY_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create an IPv4 observable for each indicator, linked by a `based-on` relationship. |
