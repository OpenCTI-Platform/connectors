# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| WIZ_CLOUD_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Tenant GraphQL endpoint, e.g. https://api.us17.app.wiz.io/graphql |
| WIZ_CLOUD_CLIENT_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Wiz service account client id |
| WIZ_CLOUD_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Wiz service account client secret |
| CONNECTOR_NAME | `string` |  | string | `"Wiz Cloud"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["wiz-cloud"]` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` |  |
| WIZ_CLOUD_AUTH_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://auth.app.wiz.io/oauth/token"` | OAuth2 token endpoint (different host than api_url) |
| WIZ_CLOUD_ISSUE_SEVERITY | `array` |  | string | `["CRITICAL", "HIGH", "MEDIUM"]` | IssueFilters.severity values to import |
| WIZ_CLOUD_ISSUE_STATUS | `array` |  | string | `["OPEN", "IN_PROGRESS"]` | IssueFilters.status values to import |
| WIZ_CLOUD_SINCE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | Relative import start on first run (ISO 8601 duration) |
| WIZ_CLOUD_PAGE_SIZE | `integer` |  | `1 <= x <= 100` | `50` |  |
| WIZ_CLOUD_MARKING | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | TLP Level Enum.<br /><br />See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/identifier.js#L76 |
