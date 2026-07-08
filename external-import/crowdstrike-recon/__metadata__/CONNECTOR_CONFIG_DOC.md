# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CROWDSTRIKE_RECON_API_BASE_URL | `string` | ✅ | string |  | API base URL. |
| CROWDSTRIKE_RECON_CLIENT_ID | `string` | ✅ | string |  | CrowdStrike Falcon Client ID. |
| CROWDSTRIKE_RECON_CLIENT_SECRET | `string` | ✅ | string |  | CrowdStrike Falcon Client Secret. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdStrike Recon"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["crowdstrike-recon"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CROWDSTRIKE_RECON_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Default TLP level of the imported entities. |
| CROWDSTRIKE_RECON_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P10D"` | ISO 8601 duration string specifying how far back to import alerts (e.g., P1D for 1 day, P7D for 7 days) |
| CROWDSTRIKE_RECON_FILTER_TOPIC | `string` |  | string | `""` | Filter notifications by topic name(s). Comma-separated string (e.g. 'SA_BRAND,SA_THIRD_PARTY_V2'). Empty means no filtering. |
| CROWDSTRIKE_RECON_FILTER_TYPE | `string` |  | string | `""` | Filter notifications by item type(s). Comma-separated string (e.g. 'typosquatting_domain,exposed_data'). Empty means no filtering. |
| CROWDSTRIKE_RECON_FILTER_PRIORITY | `string` |  | string | `""` | Filter notifications by priority(ies). Comma-separated string (e.g. 'high,medium,low'). Empty means no filtering. |
