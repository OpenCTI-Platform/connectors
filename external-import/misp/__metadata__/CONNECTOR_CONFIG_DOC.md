# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| MISP_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | MISP instance URL |
| MISP_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | MISP instance API key. |
| CONNECTOR_NAME | `string` |  | string | `"MISP"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["misp"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | The period of time to await between two runs of the connector. |
| MISP_SSL_VERIFY | `boolean` |  | boolean | `false` | Whether to check if the SSL certificate is valid when using `HTTPS` protocol or not. |
| MISP_CLIENT_CERT | `string` |  | string | `null` | Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled. |
| MISP_REFERENCE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | MISP base URL used for External References |
| MISP_CREATE_REPORTS | `boolean` |  | boolean | `true` | Whether to create reports for each imported MISP event or not. |
| MISP_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Whether to create an indicator for each imported MISP attribute or not. |
| MISP_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Whether to create an observable for each imported MISP attribute or not. |
| MISP_CREATE_OBJECT_OBSERVABLES | `boolean` |  | boolean | `false` | Whether to create a text observable for each MISP Event's object or not. |
| MISP_DATETIME_ATTRIBUTE | `string` |  | `date` `timestamp` `publish_timestamp` `sighting_timestamp` | `"timestamp"` | The attribute to use as MISP events date. |
| MISP_DATE_FILTER_FIELD | `string` |  | `date_from` `timestamp` `publish_timestamp` | `"timestamp"` | The attribute to use as filter to query new MISP events by date. |
| MISP_REPORT_DESCRIPTION_ATTRIBUTE_FILTERS | `string` |  | string | `""` | Filter to use to find the attribute that will be used for report description (example: 'type=comment,category=Internal reference') |
| MISP_CREATE_TAGS_AS_LABELS | `boolean` |  | boolean | `true` | Whether to create labels from MISP tags or not. |
| MISP_GUESS_THREATS_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to **guess** and create Threats from MISP tags or not. |
| MISP_AUTHOR_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to create Authors from MISP tags or not. |
| MISP_MARKINGS_FROM_TAGS | `boolean` |  | boolean | `false` | Whether to create Markings from MISP tags or not. |
| MISP_KEEP_ORIGINAL_TAGS_AS_LABEL | `array` |  | string | `[]` | List of original MISP tags to keep as labels. |
| MISP_ENFORCE_WARNING_LIST | `boolean` |  | boolean | `false` | Whether to enforce the warning list for MISP events or not. |
| MISP_REPORT_TYPE | `string` |  | string | `"misp-event"` | The type of report to create on OpenCTI from MISP events. |
| MISP_IMPORT_FROM_DATE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | A date (ISO-8601) from which to start importing MISP events (based on events creation date). |
| MISP_IMPORT_TAGS | `array` |  | string | `[]` | List of tags to filter MISP events to import, **including** only events with these tags. |
| MISP_IMPORT_TAGS_NOT | `array` |  | string | `[]` | List of tags to filter MISP events to import, **excluding** events with these tags. |
| MISP_IMPORT_CREATOR_ORGS | `array` |  | string | `[]` | List of organization identifiers to filter MISP events to import, **including** only events created by these organizations. |
| MISP_IMPORT_CREATOR_ORGS_NOT | `array` |  | string | `[]` | List of organization identifiers to filter MISP events to import, **excluding** events created by these organizations. |
| MISP_IMPORT_OWNER_ORGS | `array` |  | string | `[]` | List of organization identifiers to filter MISP events to import, **including** only events owned by these organizations. |
| MISP_IMPORT_OWNER_ORGS_NOT | `array` |  | string | `[]` | List of organization identifiers to filter MISP events to import, **excluding** events owned by these organizations. |
| MISP_IMPORT_KEYWORD | `string` |  | string | `null` | Keyword to use as filter to import MISP events. |
| MISP_IMPORT_DISTRIBUTION_LEVELS | `array` |  | string | `[]` | List of distribution levels to filter MISP events to import, **including** only events with these distribution levels. |
| MISP_IMPORT_THREAT_LEVELS | `array` |  | string | `[]` | List of threat levels to filter MISP events to import, **including** only events with these threat levels. |
| MISP_IMPORT_ONLY_PUBLISHED | `boolean` |  | boolean | `false` | Whether to only import published MISP events or not. |
| MISP_IMPORT_WITH_ATTACHMENTS | `boolean` |  | boolean | `false` | Whether to import attachment attribute content as a file (works only with PDF). |
| MISP_IMPORT_TO_IDS_NO_SCORE | `integer` |  | integer | `null` | A score value for the indicator/observable if the attribute `to_ids` value is no. |
| MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT | `boolean` |  | boolean | `false` | Whether to import unsupported observable as x_opencti_text or not. |
| MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT | `boolean` |  | boolean | `true` | Whether to import unsupported observable as x_opencti_text or not (just with the value). |
| MISP_PROPAGATE_LABELS | `boolean` |  | boolean | `false` | Whether to apply labels from MISP events to OpenCTI observables on top of MISP Attribute labels or not. |
| MISP_BATCH_COUNT | `integer` |  | integer | `9999` | The max number of items per batch when splitting STIX bundles. |
| MISP_REQUEST_TIMEOUT | `number` |  | number | `null` | The timeout for the requests to the MISP API in seconds. None means no timeout. |
