# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GOOGLE_DTM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Google DTM API Key |
| CONNECTOR_NAME | `string` |  | string | `"Google DTM"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["google-dtm"]` | The scope of the connector, e.g. 'google-dtm'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector in ISO 8601 format e.g., 'PT1H' for 1 hour. |
| GOOGLE_DTM_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Default Traffic Light Protocol (TLP) marking for imported data. |
| GOOGLE_DTM_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P10D"` | ISO 8601 duration string specifying how far back to import alerts (e.g., P1D for 1 day, P7D for 7 days) |
| GOOGLE_DTM_ALERT_TYPE | `array` |  | `Compromised Credentials` `Document` `Domain Discovery` `Email` `Forum Post` `Message` `Paste` `Shop Listing` `Tweet` `Web Content` | `[]` | Comma-separated list of alert types to ingest. Leave blank to retrieve alerts of all types. |
| GOOGLE_DTM_ALERT_SEVERITY | `array` |  | `high` `medium` `low` | `[]` | Comma-separated list of alert severities to ingest. Leave blank to retrieve alerts of all severities. |
