# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| KASPERSKY_USER | `string` | ✅ | string |  |  | Kaspersky Threat Intelligence Portal username. |
| KASPERSKY_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Kaspersky Threat Intelligence Portal password. |
| CONNECTOR_NAME | `string` |  | string |  | `"Kaspersky"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["kaspersky"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT12H"` | The period of time to await between two runs of the connector. |
| KASPERSKY_BASE_URL | `string` |  | string |  | `"https://tip.kaspersky.com"` | Kaspersky Threat Intelligence Portal API base URL. |
| KASPERSKY_CERTIFICATE_PATH | `string` |  | string |  | `null` | Path to the client certificate file (PEM, certificate and private key) provided by Kaspersky. When not set, no client certificate is sent. |
| KASPERSKY_TLP | `string` |  | string |  | `"Amber"` | TLP marking of the imported objects (White, Green, Amber, Red). |
| KASPERSKY_CREATE_OBSERVABLES | `boolean` |  | boolean |  | `true` | Whether to create observables from the IoCs. |
| KASPERSKY_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | Whether to create indicators from the IoCs. |
| KASPERSKY_SCOPES | `array` |  | string |  | `["publication", "master_ioc", "master_yara"]` | Comma-separated list of data to import: 'publication', 'master_ioc', 'master_yara'. |
| KASPERSKY_PUBLICATION_START_TIMESTAMP | `integer` |  | integer |  | `0` | Import publications updated after this Unix timestamp. The default value 0 imports the whole history, which is not recommended. |
| KASPERSKY_PUBLICATION_REPORT_TYPE | `string` |  | string |  | `"threat-report"` | OpenCTI report type of the publications. |
| KASPERSKY_PUBLICATION_REPORT_STATUS | `string` |  | string |  | `"New"` | OpenCTI report status of the publications (New, In progress, Analyzed, Closed). |
| KASPERSKY_PUBLICATION_REPORT_IGNORE_PREFIXES | `array` |  | string |  | `[]` | Comma-separated list of name prefixes of the publications to ignore, for example 'Monthly APT activity report'. |
| KASPERSKY_PUBLICATION_EXCLUDED_IOC_INDICATOR_TYPES | `array` |  | string |  | `[]` | Comma-separated list of OpenIOC search values to exclude from the publications, for example 'Md5sum, FileItem/Sha1sum'. |
| KASPERSKY_MASTER_IOC_FETCH_WEEKDAY | `integer` |  | integer |  | `null` | ISO weekday (1 is Monday) on which the Master IOC is fetched. When not set, the Master IOC is fetched on every run. |
| KASPERSKY_MASTER_IOC_EXCLUDED_IOC_INDICATOR_TYPES | `array` |  | string |  | `[]` | Comma-separated list of OpenIOC indicator types to exclude from the Master IOC, for example 'md5Hash, sha1Hash'. |
| KASPERSKY_MASTER_IOC_REPORT_TYPE | `string` |  | string |  | `"threat-report"` | OpenCTI report type of the Master IOC reports. |
| KASPERSKY_MASTER_IOC_REPORT_STATUS | `string` |  | string |  | `"New"` | OpenCTI report status of the Master IOC reports (New, In progress, Analyzed, Closed). |
| KASPERSKY_MASTER_YARA_FETCH_WEEKDAY | `integer` |  | integer |  | `null` | ISO weekday (1 is Monday) on which the Master YARA is fetched. When not set, the Master YARA is fetched on every run. |
| KASPERSKY_MASTER_YARA_INCLUDE_REPORT | `boolean` |  | boolean |  | `true` | Whether to create a report for each group of Master YARA rules. |
| KASPERSKY_MASTER_YARA_REPORT_TYPE | `string` |  | string |  | `"threat-report"` | OpenCTI report type of the Master YARA reports. |
| KASPERSKY_MASTER_YARA_REPORT_STATUS | `string` |  | string |  | `"New"` | OpenCTI report status of the Master YARA reports (New, In progress, Analyzed, Closed). |
| KASPERSKY_INTERVAL_SEC | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
