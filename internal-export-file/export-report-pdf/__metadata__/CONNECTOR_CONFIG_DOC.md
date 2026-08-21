# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"ExportReportPdf"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["application/pdf"]` | The scope of the connector, i.e. the MIME type of the exported files. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_EXPORT_FILE` | `"INTERNAL_EXPORT_FILE"` |  |
| EXPORT_REPORT_PDF_PRIMARY_COLOR | `string` |  | string | `"#ff8c00"` | The primary color for the output PDF (hex format, e.g. '#ff8c00'). |
| EXPORT_REPORT_PDF_SECONDARY_COLOR | `string` |  | string | `"#000000"` | The secondary color for the output PDF (hex format, e.g. '#000000'). |
| EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_1 | `string` |  | string | `null` | The first line of your company address (e.g. company name). |
| EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_2 | `string` |  | string | `null` | The second line of your company address (e.g. street address). |
| EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_3 | `string` |  | string | `null` | The third line of your company address (e.g. city, state, country). |
| EXPORT_REPORT_PDF_COMPANY_PHONE_NUMBER | `string` |  | string | `null` | The phone number of your company, displayed in the PDF footer. |
| EXPORT_REPORT_PDF_COMPANY_EMAIL | `string` |  | string | `null` | The email of your company, displayed in the PDF footer. |
| EXPORT_REPORT_PDF_COMPANY_WEBSITE | `string` |  | string | `null` | The website of your company, displayed in the PDF footer. |
| EXPORT_REPORT_PDF_INDICATORS_ONLY | `boolean` |  | boolean | `false` | Whether or not to only include Observables that are Indicators in the report. |
| EXPORT_REPORT_PDF_DEFANG_URLS | `boolean` |  | boolean | `false` | Whether or not to replace 'http' in Url observables with 'hxxp'. |
