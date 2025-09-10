# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

> ⚠️ Additional properties are not allowed.

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  |
| EMAIL_INTEL_IMAP_HOST | `string` | ✅ | string |  |  |
| EMAIL_INTEL_IMAP_USERNAME | `string` | ✅ | string |  |  |
| OPENCTI_JSON_LOGGING | `boolean` |  | boolean | `true` |  |
| OPENCTI_SSL_VERIFY | `boolean` |  | boolean | `false` |  |
| CONNECTOR_NAME | `string` |  | string | `"Email Intel IMAP"` |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["email-intel-imap"]` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warning` `error` `critical` |  |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` |  |
| CONNECTOR_EXPOSE_METRICS | `boolean` |  | boolean | `false` |  |
| CONNECTOR_METRICS_PORT | `integer` |  | integer | `9095` |  |
| CONNECTOR_ONLY_CONTEXTUAL | `boolean` |  | boolean | `false` |  |
| CONNECTOR_RUN_AND_TERMINATE | `boolean` |  | boolean | `false` |  |
| CONNECTOR_VALIDATE_BEFORE_IMPORT | `boolean` |  | boolean | `false` |  |
| CONNECTOR_QUEUE_PROTOCOL | `string` |  | string | `"amqp"` |  |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | integer | `500` |  |
| CONNECTOR_SEND_TO_QUEUE | `boolean` |  | boolean | `true` |  |
| CONNECTOR_SEND_TO_DIRECTORY | `boolean` |  | boolean | `false` |  |
| CONNECTOR_SEND_TO_DIRECTORY_PATH | `string` |  | string | `null` |  |
| CONNECTOR_SEND_TO_DIRECTORY_RETENTION | `integer` |  | integer | `7` |  |
| EMAIL_INTEL_IMAP_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` |  |
| EMAIL_INTEL_IMAP_RELATIVE_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` |  |
| EMAIL_INTEL_IMAP_PORT | `integer` |  | integer | `993` |  |
| EMAIL_INTEL_IMAP_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` |  |
| EMAIL_INTEL_IMAP_GOOGLE_TOKEN_JSON | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Content of the token.json file from Google API |
| EMAIL_INTEL_IMAP_MAILBOX | `string` |  | string | `"INBOX"` |  |
| EMAIL_INTEL_IMAP_ATTACHMENTS_MIME_TYPES | `array` |  | string | `["application/pdf", "text/csv", "text/plain"]` |  |
