# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Misp Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["misp-feed"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector. |
| MISP_FEED_SOURCE_TYPE | `string` |  | `url` `s3` | `"url"` | Source type for the MISP feed (`url` or `s3`). |
| MISP_FEED_URL | `string` |  | string | `null` | The URL of the MISP feed (required if `source_type` is `url`). |
| MISP_FEED_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify SSL certificates for the feed URL. |
| MISP_FEED_HTTP_AUTHORIZATION_HEADER | `string` |  | string | `null` | Optional value of the HTTP `Authorization` header sent on every request to the feed URL (e.g. `Basic <base64(user:password)>` or `Bearer <token>`). |
| MISP_FEED_BUCKET_NAME | `string` |  | string | `null` | Bucket Name where the MISP's files are stored |
| MISP_FEED_BUCKET_PREFIX | `string` |  | string | `null` | Used to filter imports |
| MISP_FEED_IMPORT_FROM_DATE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `null` | Start date for importing data from the MISP feed, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago). |
| MISP_FEED_CREATE_REPORTS | `boolean` |  | boolean | `true` | Whether to create reports from MISP feed data. |
| MISP_FEED_REPORT_TYPE | `string` |  | string | `"misp-event"` | The type of reports to create from the MISP feed. |
| MISP_FEED_CREATE_INDICATORS | `boolean` |  | boolean | `false` | Whether to create indicators from the MISP feed. |
| MISP_FEED_CREATE_OBSERVABLES | `boolean` |  | boolean | `false` | Whether to create observables from the MISP feed. |
| MISP_FEED_CREATE_OBJECT_OBSERVABLES | `boolean` |  | boolean | `false` | Whether to create object observables. |
| MISP_FEED_CREATE_TAGS_AS_LABELS | `boolean` |  | boolean | `true` | Whether to convert tags into labels. |
| MISP_FEED_GUESS_THREATS_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to infer threats from tags. |
| MISP_FEED_MARKINGS_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to infer markings from tags. |
| MISP_FEED_AUTHOR_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to infer authors from tags. |
| MISP_FEED_IMPORT_TO_IDS_NO_SCORE | `integer` |  | integer | `null` | Import data without a score to IDS. |
| MISP_FEED_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT | `boolean` |  | boolean | `false` | Import unsupported observables as plain text. |
| MISP_FEED_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT | `boolean` |  | boolean | `true` | Whether to import unsupported observables transparently as text. |
| MISP_FEED_IMPORT_WITH_ATTACHMENTS | `boolean` |  | boolean | `false` | Whether to import attachments from the feed. |
| AWS_ENDPOINT_URL | `string` |  | string | `null` | URL to specify for compatibility with other S3 buckets (MinIO) |
| AWS_ACCESS_KEY_ID | `string` |  | string | `null` | Access key used to access the bucket |
| AWS_SECRET_ACCESS_KEY | `string` |  | string | `null` | Secret key used to access the bucket |
