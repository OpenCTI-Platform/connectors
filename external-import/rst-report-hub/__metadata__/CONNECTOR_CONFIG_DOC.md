# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| RST_REPORT_HUB_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Your API Key for accessing RST Cloud. |
| CONNECTOR_NAME | `string` |  | string | `"RstReportHub"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| RST_REPORT_HUB_BASE_URL | `string` |  | string | `"https://api.rstcloud.net/v1"` | RST Report Hub Base URL. By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint. |
| RST_REPORT_HUB_CONNECTION_TIMEOUT | `integer` |  | integer | `30` | Connection timeout to the API in seconds. |
| RST_REPORT_HUB_READ_TIMEOUT | `integer` |  | integer | `60` | Read timeout for each feed in seconds. |
| RST_REPORT_HUB_RETRY_DELAY | `integer` |  | integer | `30` | How long to wait in seconds before next attempt to connect to the API. |
| RST_REPORT_HUB_RETRY_ATTEMPTS | `integer` |  | integer | `5` | Download retry count (number of attempts). |
| RST_REPORT_HUB_IMPORT_START_DATE | `string` |  | string | `""` | Date from which you want to retrieve the reports in the format "%Y%m%d" (for example, 20240527). By default, this start date is calculated as 7 days ago. |
| RST_REPORT_HUB_FETCH_INTERVAL | `integer` |  | integer | `300` | Fetch interval in seconds. |
| RST_REPORT_HUB_LANGUAGE | `string` |  | string | `"eng"` | Language of the RST Report Hub content. Reach out to support@rstcloud.net if you want to update this parameter. |
| RST_REPORT_HUB_CREATE_OBSERVABLES | `boolean` |  | boolean | `false` | Whether observables are to be created in addition to indicators. |
| RST_REPORT_HUB_CREATE_RELATED_TO | `boolean` |  | boolean | `true` | Whether `related-to` relationships are to be created or not. |
| RST_REPORT_HUB_CREATE_CUSTOM_TTPS | `boolean` |  | boolean | `true` | Whether `attack-pattern` objects with custom names (not present in MITRE ATT&CK) are to be created or not. |
| RST_REPORT_HUB_REPORT_LABELS_DISABLED | `string` |  | string | `""` | Comma-separated list of labels to ignore when creating Report objects. It does not prevent reports from being created. |
| RST_REPORT_HUB_SET_DETECTION_FLAG | `boolean` |  | boolean | `false` | Whether indicators from reports should be set for detection or not. |
