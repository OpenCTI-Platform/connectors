# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ImportFileMISP"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["application/json"]` | The scope (MIME types) handled by the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_IMPORT_FILE` | `"INTERNAL_IMPORT_FILE"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| MISP_IMPORT_FILE_IMPORT_FROM_DATE | `string` |  | string | `null` | Optional lower-bound date used when importing MISP events. |
| MISP_IMPORT_FILE_CREATE_REPORTS | `boolean` |  | boolean | `true` | Create a report for each imported MISP event. |
| MISP_IMPORT_FILE_REPORT_TYPE | `string` |  | string | `"misp-event"` | Report type to use for imported MISP events. |
| MISP_IMPORT_FILE_CREATE_INDICATORS | `boolean` |  | boolean | `true` | Create indicators from MISP attributes. |
| MISP_IMPORT_FILE_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create observables from MISP attributes. |
| MISP_IMPORT_FILE_CREATE_OBJECT_OBSERVABLES | `boolean` |  | boolean | `false` | Create text observables for MISP objects. |
| MISP_IMPORT_FILE_CREATE_TAGS_AS_LABELS | `boolean` |  | boolean | `true` | Create MISP tags as OpenCTI labels. |
| MISP_IMPORT_FILE_GUESS_THREATS_FROM_TAGS | `boolean` |  | boolean | `false` | Try to guess threats (threat actor, intrusion set, malware, etc.) from MISP tags when they are present in OpenCTI. |
| MISP_IMPORT_FILE_AUTHOR_FROM_TAGS | `boolean` |  | boolean | `false` | Map creator:XX=YY so the event author is derived from MISP tags. |
| MISP_IMPORT_FILE_MARKINGS_FROM_TAGS | `boolean` |  | boolean | `false` | Derive markings from MISP tags. |
| MISP_IMPORT_FILE_IMPORT_TO_IDS_NO_SCORE | `integer` |  | integer | `null` | Score applied to the indicator/observable when the attribute 'to_ids' flag is false. |
| MISP_IMPORT_FILE_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT | `boolean` |  | boolean | `false` | Import unsupported observables as x_opencti_text. |
| MISP_IMPORT_FILE_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT | `boolean` |  | boolean | `true` | Import unsupported observables as x_opencti_text just with the value. |
| MISP_IMPORT_FILE_IMPORT_WITH_ATTACHMENTS | `boolean` |  | boolean | `false` | Try to import a PDF file from the attachment attribute. |
