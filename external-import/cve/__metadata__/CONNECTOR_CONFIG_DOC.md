# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CVE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API Key for the CVE API. |
| CONNECTOR_NAME | `string` |  | string | `"NIST NVD CVE"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"cve"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CVE_BASE_URL | `string` |  | string | `"https://services.nvd.nist.gov/rest/json/cves"` | URL for the CVE API. |
| CVE_MAX_DATE_RANGE | `integer` |  | `0 < x ` | `120` | Determines how many days to collect CVE. Maximum of 120 days. |
| CVE_MAINTAIN_DATA | `boolean` |  | boolean | `true` | If set to `True`, import CVEs from the last run of the connector to the current time. Takes 2 values: `True` or `False`. |
| CVE_PULL_HISTORY | `boolean` |  | boolean | `false` | If set to `True`, import all CVEs from start year define in history start year configuration and history start year is required. Takes 2 values: `True` or `False`. |
| CVE_HISTORY_START_YEAR | `integer` |  | `0 < x ` | `2019` | Year in number. Required when pull_history is set to `True`.  Minimum 2019 as CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the cvssMetricV31 object. |
