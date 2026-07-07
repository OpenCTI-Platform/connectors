# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ZEROFOX_ALERTS_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | ZeroFox Personal Access Token (PAT) for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"ZeroFox Alerts"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["zerofox-alerts"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT15M"` | The period of time to await between two runs of the connector. |
| ZEROFOX_ALERTS_API_BASE_URL | `string` |  | string | `"https://api.zerofox.com"` | Base URL of the ZeroFox API. |
| ZEROFOX_ALERTS_MARKING | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | TLP marking definition to apply to created objects. |
| ZEROFOX_ALERTS_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | How far back to look on the first import (e.g. 'P30D' for 30 days, 'P6M' for 6 months). |
| ZEROFOX_ALERTS_ALERT_STATUSES | `array` |  | string | `["open", "escalated", "investigation_completed"]` | Alert statuses to import (comma-separated). E.g. 'open,escalated,investigation_completed'. |
| ZEROFOX_ALERTS_PAGE_SIZE | `integer` |  | `1 <= x <= 100` | `100` | Number of alerts to retrieve per API page. |
