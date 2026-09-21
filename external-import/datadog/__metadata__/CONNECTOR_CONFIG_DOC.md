# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| DATADOG_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The DataDog API key used to authenticate against the DataDog API. |
| DATADOG_APP_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The DataDog Application key. Required by the Security Monitoring v2 API, which rejects calls missing it with a 403. |
| CONNECTOR_NAME | `string` |  | string | `"DataDog"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["stix2"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. This connector drives its own polling loop from 'DATADOG_IMPORT_INTERVAL', so this value is only used to satisfy the manager-supported contract. |
| DATADOG_API_BASE_URL | `string` |  | string | `"https://api.datadoghq.com"` | The base URL of the DataDog API (site-dependent). |
| DATADOG_APP_BASE_URL | `string` |  | string | `"https://app.datadoghq.com"` | The base URL of the DataDog web application, used to build the external references pointing back to each signal. |
| DATADOG_IMPORT_INTERVAL | `integer` |  | integer | `60` | The interval, in minutes, between two runs of the connector. |
| DATADOG_IMPORT_START_DATE | `string` |  | string | `null` | The ISO 8601 date to start importing signals from on the very first run (e.g. '2024-01-01T00:00:00Z'). Defaults to 24 hours ago. |
| DATADOG_MAX_TLP | `string` |  | string | `"TLP:AMBER"` | The TLP marking applied to every emitted STIX object. Available values are: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED. |
| DATADOG_BATCH_SIZE | `integer` |  | integer | `100` | The page size used when paginating the DataDog Security Monitoring API (DataDog caps this at 1000). |
| DATADOG_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import DataDog security signals (alerts). |
| DATADOG_CREATE_INCIDENT_RESPONSE_CASES | `boolean` |  | boolean | `false` | Whether to create a Case-Incident response object for each imported security signal. |
| DATADOG_ALERT_PRIORITIES | `array` |  | string | `["P1", "P2", "P3", "P4"]` | Comma-separated list of signal priorities to import (e.g. 'P1,P2'). Defaults to every priority. |
| DATADOG_ALERT_TAGS_FILTER | `array` |  | string | `[]` | Comma-separated list of DataDog tags used to filter the imported signals (e.g. 'env:prod,team:secops'). Empty means no filtering. |
| DATADOG_EXTRACT_OBSERVABLES_FROM_ALERTS | `boolean` |  | boolean | `true` | Whether to extract the observables (IP addresses, domains, URLs, user-agents, email addresses) embedded in the signal payload. |
| DATADOG_INCLUDE_ALERT_CONTEXT | `boolean` |  | boolean | `true` | Whether to emit an explanatory Note carrying the DataDog tags, monitor query and assignee context of each signal. |
