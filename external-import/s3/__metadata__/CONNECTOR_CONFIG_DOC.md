# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| S3_ACCESS_KEY_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The AWS access key ID used to authenticate against the S3 bucket. |
| S3_SECRET_ACCESS_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The AWS secret access key used to authenticate against the S3 bucket. |
| S3_BUCKET_NAME | `string` | ✅ | string |  | The name of the S3 bucket to poll. |
| CONNECTOR_NAME | `string` |  | string | `"S3 Bucket"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["s3"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT30S"` | The period of time to await between two runs of the connector. The S3 connector schedules its runs with `S3_INTERVAL` (in seconds). |
| S3_REGION | `string` |  | string | `"us-east-1"` | The AWS region of the S3 bucket. |
| S3_ENDPOINT_URL | `string` |  | string | `null` | A custom endpoint URL, for S3-compatible services. Leave empty to target Amazon S3. |
| S3_BUCKET_PREFIXES | `array` |  | string | `["ACI_TI", "ACI_Vuln"]` | Comma-separated list of S3 bucket prefixes to process. |
| S3_AUTHOR | `string` |  | string | `null` | The organization name used as `created_by_ref` when the ingested data does not define an author. |
| S3_MARKING | `string` |  | string | `"TLP:GREEN"` | The default TLP marking applied when the ingested data does not define one. Available values are: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED. |
| S3_INTERVAL | `integer` |  | integer | `30` | The interval, in seconds, between two polls of the S3 bucket. |
| S3_ATTACH_ORIGINAL_FILE | `boolean` |  | boolean | `false` | Whether to attach the original JSON file to the vulnerabilities. |
| S3_DELETE_AFTER_IMPORT | `boolean` |  | boolean | `true` | Whether to delete the files from the S3 bucket once they are processed. Set to false to keep them for debugging purposes. |
| S3_NO_SPLIT_BUNDLES | `boolean` |  | boolean | `true` | Whether to send the STIX bundles without splitting them. |
