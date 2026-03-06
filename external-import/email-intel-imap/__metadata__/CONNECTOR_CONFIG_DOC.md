# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  |
| EMAIL_INTEL_IMAP_HOST | `string` | ✅ | string |  | IMAP server hostname or IP address |
| EMAIL_INTEL_IMAP_USERNAME | `string` | ✅ | string |  | Username to authenticate to the IMAP server. Either `password` or `google_token_json` must be set as well. |
| CONNECTOR_NAME | `string` |  | string | `"Email Intel IMAP"` | The name of the connector. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` | The type of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["email-intel-imap"]` | The scope of the connector. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warning` `error` `critical` | `"error"` | The minimum level of logs to display. |
| EMAIL_INTEL_IMAP_TLP_LEVEL | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. |
| EMAIL_INTEL_IMAP_RELATIVE_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | The relative start date to import emails in ISO 8601 duration format (e.g. P30D for 30 days). |
| EMAIL_INTEL_IMAP_PORT | `integer` |  | integer | `993` | IMAP server port number |
| EMAIL_INTEL_IMAP_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Password to authenticate to the IMAP server. Either `password` or `google_token_json` must be set. |
| EMAIL_INTEL_IMAP_GOOGLE_TOKEN_JSON | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Content of the token.json file from Google API. Either `password` or `google_token_json` must be set. |
| EMAIL_INTEL_IMAP_MAILBOX | `string` |  | string | `"INBOX"` | The mailbox to monitor (e.g., INBOX) |
| EMAIL_INTEL_IMAP_ATTACHMENTS_MIME_TYPES | `array` |  | string | `["application/pdf", "text/csv", "text/plain"]` | List of attachment MIME types to process (comma-separated) |
