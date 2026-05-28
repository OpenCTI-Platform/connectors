# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| SUBLIME_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Sublime Security API authentication token. |
| CONNECTOR_NAME | `string` |  | string | `"Sublime Security"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["sublime"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT3M"` | The period of time to await between two runs of the connector. |
| SUBLIME_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://platform.sublime.security"` | Sublime platform URL for API connections. |
| SUBLIME_INCIDENT_TYPE | `string` |  | string | `"phishing"` | Label to apply to incident type. |
| SUBLIME_INCIDENT_PREFIX | `string` |  | string | `"Sublime Incident - "` | Prefix for incident object names. |
| SUBLIME_CASE_PREFIX | `string` |  | string | `"Case - "` | Prefix for case object names. |
| SUBLIME_AUTO_CREATE_CASES | `boolean` |  | boolean | `false` | Automatically create investigation cases. |
| SUBLIME_VERDICTS | `array` |  | string | `["malicious"]` | Comma-separated attack score verdicts to process. |
| SUBLIME_SET_PRIORITY | `boolean` |  | boolean | `true` | Enable priority mapping from attack score. |
| SUBLIME_SET_SEVERITY | `boolean` |  | boolean | `true` | Enable severity mapping from attack score. |
| SUBLIME_FIRST_RUN_DURATION | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT8H"` | ISO 8601 duration for initial data fetch on first run. |
| SUBLIME_FORCE_HISTORICAL | `boolean` |  | boolean | `false` | Force historical fetch ignoring existing state for correcting improper states. |
| SUBLIME_BATCH_SIZE | `integer` |  | integer | `100` | Number of messages per processing batch. |
| SUBLIME_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking level applied to created STIX entities. |
