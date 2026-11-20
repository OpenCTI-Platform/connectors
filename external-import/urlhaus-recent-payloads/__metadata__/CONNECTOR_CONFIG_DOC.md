# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"UrlhausRecentPayloads"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT5M"` | The period of time to await between two runs of the connector. |
| URLHAUS_RECENT_PAYLOADS_AUTH_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | abuse.ch Auth-Key (community mode), available at https://auth.abuse.ch. Optional when Spamhaus credentials are set. |
| URLHAUS_RECENT_PAYLOADS_SPAMHAUS_USERNAME | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Username of the Spamhaus abuse.ch API account (commercial mode), from the Spamhaus Customer Portal. Needs `spamhaus_password`. |
| URLHAUS_RECENT_PAYLOADS_SPAMHAUS_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Password of the Spamhaus abuse.ch API account (commercial mode). Needs `spamhaus_username`. |
| URLHAUS_RECENT_PAYLOADS_API_URL | `string` |  | string |  | `"https://urlhaus-api.abuse.ch/v1/"` | The URL of the URLhaus API. |
| URLHAUS_RECENT_PAYLOADS_IMPORT_START_DATE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | `"P1D"` | Spamhaus commercial API only: how far back to fetch payloads on the first run, when the connector has no checkpoint yet. ISO-8601 datetime or duration (e.g. `P1D`). |
| URLHAUS_RECENT_PAYLOADS_INCLUDE_FILETYPES | `array` |  | string |  | `[]` | Only download files if file type matches. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_INCLUDE_SIGNATURES | `array` |  | string |  | `[]` | Only download files if match these Yara rules. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_SKIP_UNKNOWN_FILETYPES | `boolean` |  | boolean |  | `true` | Skip files with an unknown file type. |
| URLHAUS_RECENT_PAYLOADS_SKIP_NULL_SIGNATURE | `boolean` |  | boolean |  | `true` | Skip files that didn't match known Yara rules. |
| URLHAUS_RECENT_PAYLOADS_LABELS | `array` |  | string |  | `["urlhaus"]` | Labels to apply to uploaded Artifacts. (Comma separated) |
| URLHAUS_RECENT_PAYLOADS_LABELS_COLOR | `string` |  | string |  | `"#54483b"` | Color for labels specified above. |
| URLHAUS_RECENT_PAYLOADS_SIGNATURE_LABEL_COLOR | `string` |  | string |  | `"#0059f7"` | Color for Yara rule match label. |
| URLHAUS_RECENT_PAYLOADS_FILETYPE_LABEL_COLOR | `string` |  | string |  | `"#54483b"` | Color to use for filetype label. |
| URLHAUS_RECENT_PAYLOADS_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Use URLHAUS_RECENT_PAYLOADS_AUTH_KEY instead. |
