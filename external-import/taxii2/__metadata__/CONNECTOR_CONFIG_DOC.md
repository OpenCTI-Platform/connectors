# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| TAXII2_DISCOVERY_URL | `string` | ✅ | string |  | The TAXII 2 server discovery URL. |
| CONNECTOR_NAME | `string` |  | string | `"TAXII2"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["ipv4-addr", "ipv6-addr", "vulnerability", "domain", "url", "file-sha256", "file-md5", "file-sha1"]` | The scope of the connector, i.e. the observable types to import. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| TAXII2_USERNAME | `string` |  | string | `null` | The username used for basic authentication against the TAXII server. |
| TAXII2_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | The password used for basic authentication against the TAXII server. |
| TAXII2_USE_TOKEN | `boolean` |  | boolean | `false` | Whether to use bearer token authentication instead of basic authentication. |
| TAXII2_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | The bearer token used to authenticate against the TAXII server. |
| TAXII2_USE_APIKEY | `boolean` |  | boolean | `false` | Whether to use API key authentication instead of basic authentication. |
| TAXII2_APIKEY_KEY | `string` |  | string | `null` | The name of the HTTP header holding the API key. |
| TAXII2_APIKEY_VALUE | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | The value of the API key sent in the API key HTTP header. |
| TAXII2_USE_CERT | `boolean` |  | boolean | `false` | Whether to use a client certificate (mTLS) to connect to the TAXII server. |
| TAXII2_CERT_PATH | `string` |  | string | `null` | The path to the client certificate used for mTLS. |
| TAXII2_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the SSL certificate of the TAXII server. |
| TAXII2_V21 | `boolean` |  | boolean | `true` | Whether the TAXII server is TAXII 2.1 compliant. Set to `false` for TAXII 2.0. |
| TAXII2_COLLECTIONS | `array` |  | string | `["*.*"]` | The collections to poll, formatted as `api_root.collection`. Wildcards are supported, e.g. `*.*` to poll every collection of every API root. |
| TAXII2_INITIAL_HISTORY | `integer` |  | integer | `24` | The number of hours of history to fetch during the first run. |
| TAXII2_INTERVAL | `integer` |  | integer | `1` | The number of hours to await between two runs of the connector. Only used when `CONNECTOR_DURATION_PERIOD` is not set. |
| TAXII2_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Whether to create indicators from the imported observables. |
| TAXII2_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create observables from the imported indicators. |
| TAXII2_ADD_CUSTOM_LABEL | `boolean` |  | boolean | `false` | Whether to add a custom label to all the imported objects. |
| TAXII2_CUSTOM_LABEL | `string` |  | string | `null` | The custom label to add to all the imported objects. |
| TAXII2_FORCE_PATTERN_AS_NAME | `boolean` |  | boolean | `false` | Whether to use the indicator pattern as the indicator name. |
| TAXII2_FORCE_MULTIPLE_PATTERN_NAME | `string` |  | string | `null` | The name to give to indicators holding multiple patterns. |
| TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL | `boolean` |  | boolean | `false` | Whether to convert a custom STIX property into an OpenCTI label. |
| TAXII2_STIX_CUSTOM_PROPERTY | `string` |  | string | `null` | The name of the custom STIX property to convert into a label. |
| TAXII2_ENABLE_URL_QUERY_LIMIT | `boolean` |  | boolean | `false` | Whether to add a `limit` query parameter to the TAXII server requests. Only supported by TAXII 2.1 servers. |
| TAXII2_URL_QUERY_LIMIT | `integer` |  | integer | `100` | The value of the `limit` query parameter sent to the TAXII server. |
| TAXII2_DETERMINE_X_OPENCTI_SCORE_BY_LABEL | `boolean` |  | boolean | `false` | Whether to determine the OpenCTI score of an indicator from its labels. |
| TAXII2_DEFAULT_X_OPENCTI_SCORE | `integer` |  | integer | `50` | The OpenCTI score to set when no label matches. |
| TAXII2_INDICATOR_HIGH_SCORE_LABELS | `array` |  | string | `[]` | The labels triggering the high OpenCTI score. |
| TAXII2_INDICATOR_HIGH_SCORE | `integer` |  | integer | `80` | The OpenCTI score to set for indicators matching a high score label. |
| TAXII2_INDICATOR_MEDIUM_SCORE_LABELS | `array` |  | string | `[]` | The labels triggering the medium OpenCTI score. |
| TAXII2_INDICATOR_MEDIUM_SCORE | `integer` |  | integer | `60` | The OpenCTI score to set for indicators matching a medium score label. |
| TAXII2_INDICATOR_LOW_SCORE_LABELS | `array` |  | string | `[]` | The labels triggering the low OpenCTI score. |
| TAXII2_INDICATOR_LOW_SCORE | `integer` |  | integer | `40` | The OpenCTI score to set for indicators matching a low score label. |
| TAXII2_SET_INDICATOR_AS_DETECTION | `boolean` |  | boolean | `false` | Whether to flag the imported indicators as detection. |
| TAXII2_CREATE_AUTHOR | `boolean` |  | boolean | `false` | Whether to create an author identity and link it to the imported objects. |
| TAXII2_AUTHOR_NAME | `string` |  | string | `null` | The name of the author identity to create. |
| TAXII2_AUTHOR_DESCRIPTION | `string` |  | string | `null` | The description of the author identity to create. |
| TAXII2_AUTHOR_RELIABILITY | `string` |  | string | `null` | The reliability of the author identity to create, e.g. `A - Completely reliable`. |
| TAXII2_EXCLUDE_SPECIFIC_LABELS | `boolean` |  | boolean | `false` | Whether to exclude some labels from the imported objects. |
| TAXII2_LABELS_TO_EXCLUDE | `array` |  | string | `[]` | The regular expressions matching the labels to exclude. |
| TAXII2_REPLACE_CHARACTERS_IN_LABEL | `boolean` |  | boolean | `false` | Whether to replace characters in the imported labels. |
| TAXII2_CHARACTERS_TO_REPLACE_IN_LABEL | `array` |  | string | `[]` | The replacement rules to apply to labels, formatted as a comma-separated list of `find:replace` pairs. |
| TAXII2_IGNORE_PATTERN_TYPES | `boolean` |  | boolean | `false` | Whether to ignore indicators based on their pattern type. |
| TAXII2_PATTERN_TYPES_TO_IGNORE | `array` |  | string | `[]` | The indicator pattern types to ignore, e.g. `stix, yara`. |
| TAXII2_IGNORE_OBJECT_TYPES | `boolean` |  | boolean | `false` | Whether to ignore STIX objects based on their type. |
| TAXII2_OBJECT_TYPES_TO_IGNORE | `array` |  | string | `[]` | The STIX object types to ignore, e.g. `report, note`. |
| TAXII2_IGNORE_SPECIFIC_PATTERNS | `boolean` |  | boolean | `false` | Whether to ignore indicators based on their pattern content. |
| TAXII2_PATTERNS_TO_IGNORE | `array` |  | string | `[]` | The indicator pattern contents to ignore. |
| TAXII2_IGNORE_SPECIFIC_NOTES | `boolean` |  | boolean | `false` | Whether to ignore notes based on their content. |
| TAXII2_NOTES_TO_IGNORE | `array` |  | string | `[]` | The note contents to ignore. |
| TAXII2_SAVE_ORIGINAL_INDICATOR_ID_TO_NOTE | `boolean` |  | boolean | `false` | Whether to save the original indicator ID into an OpenCTI note. |
| TAXII2_SAVE_ORIGINAL_INDICATOR_ID_ABSTRACT | `string` |  | string | `null` | The abstract of the note holding the original indicator ID. |
| TAXII2_CHANGE_REPORT_STATUS | `boolean` |  | boolean | `false` | Whether to override the workflow status of the imported reports. |
| TAXII2_CHANGE_REPORT_STATUS_X_OPENCTI_WORKFLOW_ID | `string` |  | string | `null` | The OpenCTI workflow status ID to set on the imported reports. |
