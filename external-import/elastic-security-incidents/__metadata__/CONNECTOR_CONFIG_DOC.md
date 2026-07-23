# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| ELASTIC_SECURITY_URL | `string` | ✅ | string |  | The Elasticsearch URL (for alerts) or Kibana URL (for cases). |
| ELASTIC_SECURITY_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The Elasticsearch API Key. |
| CONNECTOR_NAME | `string` |  | string | `"Elastic Security Incidents"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["elastic-security-incidents"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT30M"` | The period of time to await between two runs of the connector. |
| ELASTIC_SECURITY_KIBANA_URL | `string` |  | string | `null` | The Kibana URL (optional, required for cases if different from Elasticsearch URL). |
| ELASTIC_SECURITY_CA_CERT | `string` |  | string | `null` | Path to CA certificate for SSL verification (optional). |
| ELASTIC_SECURITY_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify SSL certificates. |
| ELASTIC_SECURITY_IMPORT_START_DATE | `string` |  | string | `null` | Initial import start date in ISO-8601 format (e.g. 2024-01-01T00:00:00Z). |
| ELASTIC_SECURITY_IMPORT_ALERTS | `boolean` |  | boolean | `true` | Whether to import security alerts. |
| ELASTIC_SECURITY_IMPORT_CASES | `boolean` |  | boolean | `true` | Whether to import security cases (requires Kibana URL). |
| ELASTIC_SECURITY_ALERT_STATUSES | `array` |  | string | `[]` | Alert statuses to import (comma-separated). Leave empty to import all. |
| ELASTIC_SECURITY_ALERT_RULE_TAGS | `array` |  | string | `[]` | Alert rule tags to filter by (comma-separated). Leave empty to import all. |
| ELASTIC_SECURITY_CASE_STATUSES | `array` |  | string | `[]` | Case statuses to import (comma-separated). Leave empty to import all. |
