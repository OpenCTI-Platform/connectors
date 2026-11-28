# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"OffSeq Mirage"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "IPv4-Addr", "Url", "StixFile", "Attack-Pattern", "Vulnerability"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs, as an ISO 8601 duration. The feed is rebuilt once a day; an unchanged bundle is skipped. |
| OFFSEQ_MIRAGE_FEED_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://feeds.offseq.com/mirage-feed/latest/stix/mirage.json"` | URL of the Mirage Feed STIX 2.1 bundle. |
| OFFSEQ_MIRAGE_IMPORT_RELATIONSHIPS | `boolean` |  | boolean | `true` | Import the ATT&CK techniques and CVEs each indicator is linked to, with `indicates` and `related-to` relationships. |
| OFFSEQ_MIRAGE_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create the observable behind each indicator, with a `based-on` relationship. |
| OFFSEQ_MIRAGE_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object this connector creates. The feed is published as TLP:CLEAR. |
| OFFSEQ_MIRAGE_BATCH_SIZE | `integer` |  | `100 <= x <= 5000` | `1000` | Indicators per bundle sent to OpenCTI. |
