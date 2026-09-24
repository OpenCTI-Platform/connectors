# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| HONEYLABS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | A HoneyLabs API key. Free keys are created at https://honeylabs.net/dashboard. It is sent as the HTTP Basic password on the TAXII server, with the fixed username `taxii`. |
| CONNECTOR_NAME | `string` |  | string | `"HoneyLabs"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "IPv4-Addr", "Url"]` | The scope of the connector e.g., the type of entities the connector imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). The feeds refresh every 15 minutes; hourly is the sensible floor. |
| HONEYLABS_API_ROOT | `string` |  | string | `"https://honeylabs.net/taxii2/api/"` | The TAXII 2.1 API root of the HoneyLabs server. |
| HONEYLABS_COLLECTIONS | `array` |  | string | `["attackers", "malware-infrastructure"]` | Which HoneyLabs collections to import, by alias. `attackers` is the union of `exploiters` (addresses that ran exploit or loader commands against the sensors) and, on paid plans, `cve-probers` (addresses that probed a specific CVE's exploit path, labelled with the CVE ids). `malware-infrastructure` is the loader and C2 URLs pulled out of captured payloads. |
| HONEYLABS_IMPORT_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Start date for the first import (ISO 8601, absolute like '2026-01-01T00:00:00Z' or relative like 'P7D'). Later runs resume from the connector state. The free plan serves 7 days of history, paid plans 30. |
| HONEYLABS_PAGE_SIZE | `integer` |  | integer | `500` | Objects requested per TAXII page. |
| HONEYLABS_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create the IPv4 address and URL observables behind each indicator, with a `based-on` relationship. |
| HONEYLABS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object this connector creates. |
