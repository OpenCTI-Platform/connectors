# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ORKL"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["orkl"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | The period of time to await between two runs of the connector. |
| ORKL_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://orkl.eu/api/v1"` | Base URL of the ORKL API. |
| ORKL_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | How far back to look on the first import (e.g. 'P30D' for 30 days, 'P6M' for 6 months). |
| ORKL_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking level applied to created STIX objects. |
| ORKL_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean | `true` | Create ORKL threat actors as Intrusion Sets (true) or as Threat Actors (false). |
| ORKL_INGEST_TOOLS | `boolean` |  | boolean | `false` | Create Tool entities from the threat actors' tools. Disabled by default: the ORKL feed does not distinguish malware from tools, so enabling this will create Tool entities for what are in fact malware families. |
