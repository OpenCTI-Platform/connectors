# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI platform. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token of the OpenCTI user representing the connector. |
| THREATLANDSCAPE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authenticating with the Threat Landscape API. |
| THREATLANDSCAPE_FEED | `string` | ✅ | `intelligence` `intelligence-osint` `intelligence-darknet` `ioc` |  | Feed to ingest. `intelligence` ingests full STIX bundles from both OSINT and darknet sources. `intelligence-osint` restricts to OSINT only. `intelligence-darknet` restricts to darknet only. `ioc` ingests lean actionable indicators from the IOC feed. |
| CONNECTOR_NAME | `string` |  | string | `"Threat Landscape"` | The name of the connector as displayed in OpenCTI. |
| CONNECTOR_SCOPE | `array` |  | string | `["indicator","report","threat-actor","malware","campaign","intrusion-set","attack-pattern","vulnerability","identity","location"]` | The STIX object types this connector imports. Adjust to match the selected feed (e.g. use `indicator,identity` for the ioc feed). |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Minimum log level to display. Use `debug` for troubleshooting. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | ISO 8601 duration defining the interval between connector runs. |
| THREATLANDSCAPE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.threatlandscape.io/rest/v1"` | Base URL of the Threat Landscape REST API. Override only if using a custom deployment. |
| THREATLANDSCAPE_IMPORT_SINCE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P30D"` | ISO 8601 duration for the initial lookback window on the first run only. Subsequent runs use a sequence cursor and ignore this value. |
| THREATLANDSCAPE_PAGE_SIZE | `integer` |  | `1 <= x <= 1000` | `100` | Number of records fetched per API request. |
