# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| BITDEFENDER_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | | Threat Intelligence license key from Bitdefender |
| BITDEFENDER_FEEDS | `string` | ✅ | `file,ip,web` | | Comma-separated list of Threat Intel feeds to import. Supported values are `file` (file reputation feed), `web` (Web reputation feed) and `ip` (IP reputation feed). Feeds must be available in your license |
| BITDEFENDER_MIN_CONFIDENCE  | `number` | | 1-99 | 75 | Defines the minimal confidence level (1-99) for the feed entry to be imported. Default is 75. |
| BITDEFENDER_MIN_SEVERITY    | `number` | | 1-100 | 100 | Number; defines the minimal severity level (1-99) for the feed entry to be imported. Default is 1 |
| BITDEFENDER_INCLUDE_REVOKED | `string` | | true/false/only | true | Defines whether to include the indicators for revoked entries. Can be "true" (include), "false" (exclude those; default), and "only (only import those entries) |
| BITDEFENDER_EXCLUDE_RELATED_INDICATORS | `boolean` | | true/false | false | Defines whether to exclude the related indicators (which provide relationship data). By default those are included |
| BITDEFENDER_INCLUDE_SUSPICIOUS | `string` | | true/false/only | false | Defines whether to include the entries which are marked as suspicious. Can be "true" (include), "false" (exclude those; default), and "only (only import those entries) |
| BITDEFENDER_DETECTION | `boolean`| | true/false | true | Set `x_opencti_detection` on created indicators. Default: `false`. |
| BITDEFENDER_CREATE_MALWARE_OBJECTS | `boolean` | | true/false | true | Create a Malware entity for each file detection (`true`, default), or only Malware family entities (`false`). |
| BITDEFENDER_TLP_LEVEL | `string` | | `clear` `white`, `green`, `amber`, `amber+strict`, or `red` | clear | Default marking for imported indicators, observables, Malware entities and relationships. |
