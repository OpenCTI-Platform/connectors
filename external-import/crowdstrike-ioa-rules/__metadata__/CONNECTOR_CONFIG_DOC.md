# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| CROWDSTRIKE_IOA_RULES_CLIENT_ID | `string` | ✅ | Length: `string >= 1` |  | API client id. The API client needs the `Custom IOA rules: Read` scope, and `Prevention policies: Read` to check prevention policy assignments. |
| CROWDSTRIKE_IOA_RULES_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API client secret. |
| CONNECTOR_NAME | `string` |  | string | `"CrowdStrike Falcon Custom IOA Rules"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Attack-Pattern", "SecurityPlatform"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). Every run reads the full rule set. |
| CROWDSTRIKE_IOA_RULES_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://api.crowdstrike.com/"` | CrowdStrike API base URL of your cloud: `https://api.crowdstrike.com` (US-1), `https://api.us-2.crowdstrike.com` (US-2), `https://api.eu-1.crowdstrike.com` (EU-1), `https://api.laggar.gcw.crowdstrike.com` (US-GOV-1). |
| CROWDSTRIKE_IOA_RULES_MEMBER_CID | `string` |  | string | `null` | Child CID to read, for Flight Control (MSSP) parent API clients. |
| CROWDSTRIKE_IOA_RULES_RULE_GROUP_FILTER | `string` |  | string | `null` | Optional FQL filter on rule groups, e.g. `platform:'windows'`. |
| CROWDSTRIKE_IOA_RULES_CHECK_PREVENTION_POLICIES | `boolean` |  | boolean | `true` | Only count a rule as `active` when its rule group is assigned to an enabled prevention policy (a group runs on the hosts of its policies only). Needs the `Prevention policies: Read` scope; without it, a warning is logged and only the enabled state of rules and groups counts. |
| CROWDSTRIKE_IOA_RULES_IMPORT_DISABLED_RULES | `boolean` |  | boolean | `true` | Import inactive rules too (disabled rules, rules of disabled groups or of groups assigned to no enabled prevention policy), with the deployment status `deployed` (active ones get `active`). When false, they are left out and count as removed. |
| CROWDSTRIKE_IOA_RULES_PAGE_SIZE | `integer` |  | `1 <= x <= 500` | `100` | Rule group ids requested per page. |
| CROWDSTRIKE_IOA_RULES_REQUEST_TIMEOUT | `integer` |  | `1 <= x ` | `60` | Timeout of each HTTP request, in seconds. |
| CROWDSTRIKE_IOA_RULES_MAX_RETRIES | `integer` |  | `0 <= x ` | `5` | Retries of a request failing with a rate limit (429), a server error (5xx) or a network error, with exponential backoff. |
| CROWDSTRIKE_IOA_RULES_PLATFORM_NAME | `string` |  | Length: `string >= 1` | `"CrowdStrike Falcon"` | Name of the Security Platform the rules are deployed on in OpenCTI. |
| CROWDSTRIKE_IOA_RULES_PLATFORM_ID | `string` |  | Length: `string >= 1` | `null` | Id (internal or STIX) of an existing Security Platform in OpenCTI the rules are deployed on, for example the one the CrowdStrike stream connector of the same tenant reports to. Takes precedence over `platform_name` and `platform_type`: the connector references that platform and never rewrites it. |
| CROWDSTRIKE_IOA_RULES_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"EDR"` | Type of that Security Platform (`security_platform_type`). |
| CROWDSTRIKE_IOA_RULES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
