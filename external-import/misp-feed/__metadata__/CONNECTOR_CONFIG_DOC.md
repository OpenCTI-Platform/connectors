# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_SCOPE | `array` | ✅ | string |  | The scope of the connector, e.g. 'flashpoint'. |
| CONNECTOR_NAME | `string` |  | string | `"Misp Feed"` | The name of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector. |
| MISP_FEED_SOURCE_TYPE | `string` |  | `url` `s3` | `"url"` | Source type for the MISP feed (`url` or `s3`). |
| MISP_FEED_URL | `string` |  | string | `null` | The URL of the MISP feed (required if `source_type` is `url`). |
| MISP_FEED_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify SSL certificates for the feed URL. |
| MISP_FEED_BUCKET_NAME | `string` |  | string | `null` | Bucket Name where the MISP's files are stored |
| MISP_FEED_BUCKET_PREFIX | `string` |  | string | `null` | Used to filter imports |
| MISP_FEED_IMPORT_FROM_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Start date for importing data from the MISP feed. |
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
