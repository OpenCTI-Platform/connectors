# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| KASPERSKY_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate requests to the Kaspersky service. |
| CONNECTOR_NAME | `string` |  | string | `"Kaspersky Enrichment"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | If True, the connector will automatically import data from the API. |
| KASPERSKY_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://tip.kaspersky.com/"` | Kaspersky API base URL. |
| KASPERSKY_ZONE_OCTI_SCORE_MAPPING | `string` |  | string | `"red:100,orange:80,yellow:60,gray:20,green:0"` | Zone to score mapping. Only the numerical value need to be changed if necessary. See https://tip.kaspersky.com/Help/Doc_data/en-US/AboutZones.htm for further explanations |
| KASPERSKY_FILE_SECTIONS | `string` |  | Length: `string >= 1` | `"LicenseInfo,Zone,FileGeneralInfo"` | Sections wanted to investigate for the requested hash. LicenseInfo, Zone and FileGeneralInfo are always set, can't be disabled. Only DetectionsInfo, FileDownloadedFromUrls, Industries and FileNames are currently supported |
