# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| POLYSWARM_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | PolySwarm API key. Used as the TAXII Basic auth password and for the live hunting API. |
| POLYSWARM_ACCOUNT_NUMBER | `string` | ✅ | Length: `string >= 1` |  | PolySwarm account number. Used as the TAXII Basic auth username. |
| CONNECTOR_NAME | `string` |  | string | `"PolySwarm Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Malware", "Indicator", "StixFile", "Malware-Analysis", "Attack-Pattern", "Note"]` | The scope of the connector, i.e. the types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). |
| POLYSWARM_API_URL | `string` |  | string | `"https://api.polyswarm.network"` | PolySwarm API base URL. The connector appends the `/v3/...` paths. |
| POLYSWARM_FEED_COLLECTIONS | `array` |  | string | `["trustgroup"]` | Comma-separated list of PolySwarm TAXII API roots to import. Allowed values: trustgroup, ransomware, freemium. |
| POLYSWARM_FEED_BACKFILL_DAYS | `integer` |  | `1 <= x ` | `14` | On the first run only, how many days of feed data to import. |
| POLYSWARM_FEED_INDICATOR_VALID_DAYS | `integer` |  | `1 <= x ` | `90` | Feed indicators are valid until import time plus this many days. |
| POLYSWARM_FEED_FAMILIES | `array` |  | string | `[]` | Optional comma-separated list of malware family names. When set, only feed samples whose family is in the list are imported. Names are compared without regard to case. Empty means no filtering. |
| POLYSWARM_FEED_EXCLUDE_FAMILIES | `array` |  | string | `[]` | Optional comma-separated list of malware family names. Feed samples whose family is in the list are skipped. Names are compared without regard to case. Empty means no filtering. |
| POLYSWARM_FEED_MIN_CONFIDENCE | `integer` |  | `0 <= x <= 100` | `null` | Optional minimum malware confidence (0 to 100). Feed samples whose malware confidence is below this value are skipped. Samples that carry no confidence are kept. Unset means no filtering. |
| POLYSWARM_HUNTING_ENABLED | `boolean` |  | boolean | `false` | Import live hunting results (YARA rule matches) of the account. |
| POLYSWARM_HUNTING_BACKFILL_HOURS | `integer` |  | `1 <= x ` | `24` | On the first run only, how many hours of live hunting results to import. |
| POLYSWARM_HUNTING_INDICATOR_VALID_DAYS | `integer` |  | `1 <= x ` | `30` | Live hunting indicators are valid until import time plus this many days. |
| POLYSWARM_QUOTA_WARN_BELOW | `integer` |  | `0 <= x ` | `100` | Log a warning when the remaining daily API quota, or a sandbox or hunt allowance, falls below this number (0 = no warnings). Accounts with no cap are never warned. |
| POLYSWARM_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | TLP marking applied to every object the connector sends. |
| POLYSWARM_MAX_OBJECTS_PER_RUN | `integer` |  | `1 <= x ` | `20000` | Stop paging once this many objects were sent in a run. The next run resumes where this one stopped. |
