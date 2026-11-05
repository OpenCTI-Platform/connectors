# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| ACCENTURE_ACTI_USERNAME | `string` | ✅ | string |  |  | The username of the Accenture ACTI account used to authenticate. |
| ACCENTURE_ACTI_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The password of the Accenture ACTI account used to authenticate. |
| ACCENTURE_ACTI_USER_POOL_ID | `string` | ✅ | string |  |  | The AWS Cognito user pool ID provided by Accenture ACTI. |
| ACCENTURE_ACTI_CLIENT_ID | `string` | ✅ | string |  |  | The AWS Cognito client ID provided by Accenture ACTI. |
| ACCENTURE_ACTI_S3_BUCKET_NAME | `string` | ✅ | string |  |  | The name of the Accenture ACTI S3 bucket to collect data from. |
| ACCENTURE_ACTI_S3_BUCKET_REGION | `string` | ✅ | string |  |  | The AWS region of the Accenture ACTI S3 bucket. |
| ACCENTURE_ACTI_S3_BUCKET_ACCESS_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The AWS access key used to read the Accenture ACTI S3 bucket. |
| ACCENTURE_ACTI_S3_BUCKET_SECRET_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The AWS secret key used to read the Accenture ACTI S3 bucket. |
| CONNECTOR_NAME | `string` |  | string |  | `"Accenture ACTI"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["accenture"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| ACCENTURE_ACTI_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | The TLP marking applied to the imported data. |
| ACCENTURE_ACTI_RELATIVE_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P30D"` | The relative period of time to look back for the first import. |
| ACCENTURE_ACTI_THREAT_ACTOR_AS_INTRUSION_SET | `boolean` |  | boolean |  | `true` | Whether to convert imported threat actors into intrusion sets. |
| ACCENTURE_ACTI_CLIENT_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | ⛔️ | `null` | Use ACCENTURE_ACTI_TLP_LEVEL instead. (removal scheduled for 2027-06-30) |
