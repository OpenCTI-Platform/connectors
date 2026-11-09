# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| DOMAINTOOLS_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API base URL. |
| DOMAINTOOLS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authentication. |
| DOMAINTOOLS_FEED_TYPE | `string` | ✅ | `domainhotlist` `domainrisk` `nod` `nad` `noh` `domaindiscovery` |  | Name of the feed. |
| CONNECTOR_NAME | `string` |  | string | `"DomainToolsFeedsConnector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["domaintools-feeds"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| DOMAINTOOLS_SESSION_ID | `string` |  | string | `"OpenCTI-DomainTools-Feeds"` | A unique identifier for the session, used for resuming data retrieval from the last point. |
| DOMAINTOOLS_DOMAIN | `string` |  | string | `null` | Filter for an exact domain or a domain substring by prefixing or suffixing your string with *. |
| DOMAINTOOLS_TOP | `integer` |  | integer | `null` | Limits the number of results in the response payload. Primarily intended for testing. |
| DOMAINTOOLS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP level of the imported entities. |
