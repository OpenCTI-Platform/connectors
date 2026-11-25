# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"Urlhaus"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT3H"` | The period of time to await between two runs of the connector. |
| URLHAUS_AUTH_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | abuse.ch Auth-Key, available at https://auth.abuse.ch. Required unless `csv_url` is set. |
| URLHAUS_CSV_URL | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `null` | Override of the URLhaus CSV export URL. Defaults to https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv, built from `auth_key`. The retired public URL (https://urlhaus.abuse.ch/downloads/...) is ignored. |
| URLHAUS_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer |  | `80` | Default x_opencti_score for imported indicators. |
| URLHAUS_IMPORT_OFFLINE | `boolean` |  | boolean |  | `true` | Import URLs marked as 'offline' in addition to 'online'. |
| URLHAUS_THREATS_FROM_LABELS | `boolean` |  | boolean |  | `true` | Create relationships to existing threats based on URL tags. |
| URLHAUS_INTERVAL | `integer` |  | integer | ⛔️ | `3` | Polling interval in hours. |
