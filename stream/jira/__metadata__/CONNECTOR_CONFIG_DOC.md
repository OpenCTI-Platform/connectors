# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_LIVE_STREAM_ID | `string` | ✅ | string |  | The ID of the live stream to connect to. |
| JIRA_URL | `string` | ✅ | string |  | URL to Jira server (e.g., https://yourinstance.atlassian.net). |
| JIRA_LOGIN_EMAIL | `string` | ✅ | string |  | Email for Jira account with API access. |
| JIRA_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token for Jira authentication. |
| JIRA_PROJECT_KEY | `string` | ✅ | string |  | Jira project key (not name) for issue creation. |
| CONNECTOR_NAME | `string` |  | string | `"Atlassian JIRA"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["jira"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `STREAM` | `"STREAM"` |  |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | `boolean` |  | boolean | `true` | Whether to listen for delete events on the live stream. |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | `boolean` |  | boolean | `true` | Whether to ignore dependencies when processing events from the live stream. |
| JIRA_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify SSL certificates. |
| JIRA_ISSUE_TYPE_NAME | `string` |  | string | `"Task"` | Issue type to create (Epic, Task, etc.). |
| JIRA_CUSTOM_FIELDS_KEYS | `string` |  | string | `""` | Comma-separated custom field IDs (e.g., customfield_10039). |
| JIRA_CUSTOM_FIELDS_VALUES | `string` |  | string | `""` | Comma-separated values for custom fields (same order). |
