# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  |
| EMAIL_INTEL_MICROSOFT_TENANT_ID | `string` | ✅ | string |  |  |
| EMAIL_INTEL_MICROSOFT_CLIENT_ID | `string` | ✅ | string |  |  |
| EMAIL_INTEL_MICROSOFT_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| EMAIL_INTEL_MICROSOFT_EMAIL | `string` | ✅ | Format: [`email`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| CONNECTOR_NAME | `string` |  | string | `"Email Intel Microsoft"` |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["email-intel-microsoft"]` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warning` `error` `critical` | `"error"` |  |
| EMAIL_INTEL_MICROSOFT_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` |  |
| EMAIL_INTEL_MICROSOFT_RELATIVE_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` |  |
| EMAIL_INTEL_MICROSOFT_MAILBOX | `string` |  | string | `"INBOX"` |  |
| EMAIL_INTEL_MICROSOFT_ATTACHMENTS_MIME_TYPES | `array` |  | string | `["application/pdf", "text/csv", "text/plain"]` |  |
