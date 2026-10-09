# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CROWDSTRIKE_INCIDENTS_CLIENT_ID | `string` | ✅ | string |  | CrowdStrike API client ID. The API client needs the 'Alerts: Read' scope. |
| CROWDSTRIKE_INCIDENTS_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CrowdStrike API client secret. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdStrike Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crowdstrike-incidents"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector (e.g. 'PT5M' for 5 minutes). |
| CROWDSTRIKE_INCIDENTS_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.crowdstrike.com"` | Base URL of the CrowdStrike API for the tenant's cloud region (e.g. 'https://api.us-2.crowdstrike.com', 'https://api.eu-1.crowdstrike.com'). |
| CROWDSTRIKE_INCIDENTS_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P7D"` | How far back to look on the first import (e.g. 'P7D' for 7 days, 'P30D' for 30 days). |
| CROWDSTRIKE_INCIDENTS_PRODUCTS | `array` |  | string | `["ngsiem"]` | Comma-separated list of CrowdStrike alert products to import. Only 'ngsiem' (Next-Gen SIEM) is supported for now; other values are ignored. |
| CROWDSTRIKE_INCIDENTS_SEVERITY_MIN | `string` |  | `informational` `low` `medium` `high` `critical` | `null` | Minimum severity of the alerts to import: 'informational', 'low', 'medium', 'high' or 'critical'. All alerts are imported when unset. |
| CROWDSTRIKE_INCIDENTS_INCLUDE_HIDDEN | `boolean` |  | boolean | `false` | Whether to also import alerts hidden in the Falcon console. |
| CROWDSTRIKE_INCIDENTS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | TLP marking level applied to every created STIX object. |
