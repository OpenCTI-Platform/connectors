# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| FLARE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Flare API key. |
| CONNECTOR_NAME | `string` |  | string |  | `"Flare"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Flare"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs. |
| FLARE_API_DOMAIN | `string` |  | string |  | `"api.flare.io"` | API domain name. |
| FLARE_TENANT_ID | `integer` |  | integer |  | `null` | Flare tenant ID. |
| FLARE_EVENT_TYPES | `array` |  | string |  | `["stealer_log", "domain", "ransomleak", "leak"]` | Comma-separated list of Flare event types to import. |
| FLARE_EVENT_ACTIONS | `array` |  | string |  | `[]` | Comma-separated list of event actions to filter by. If not set, all actions are imported. |
| FLARE_LOOKBACK_DAYS | `integer` |  | integer |  | `30` | Number of days to look back on the first run. |
| FLARE_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"white"` | Default TLP level of the imported entities. |
| FLARE_API_BASE_URL | `string` |  | string | ⛔️ | `null` | Use FLARE_API_DOMAIN instead. (removal scheduled for 2027-06-30) |
