# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"CVEProject cvelistV5"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["identity", "vulnerability", "software"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). |
| CVELISTV5_REPO_URL | `string` |  | string | `"https://github.com/CVEProject/cvelistV5.git"` | Upstream git repository. Override only if you mirror cvelistV5 internally. |
| CVELISTV5_REPO_BRANCH | `string` |  | string | `"main"` | Branch of the upstream git repository to follow. |
| CVELISTV5_LOCAL_PATH | `string` |  | string | `"/opt/cvelistV5"` | Local path where the clone is kept. Must be writable by the connector; mount a volume there to keep the clone across restarts. |
| CVELISTV5_HISTORY_START_YEAR | `integer` |  | integer | `2024` | Oldest year of CVE records to import on the initial run (minimum 1999; a lower value falls back to the default). |
