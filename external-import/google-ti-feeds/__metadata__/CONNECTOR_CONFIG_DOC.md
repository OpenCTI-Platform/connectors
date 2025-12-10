# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The URL of the OpenCTI platform instance | ```http://localhost:8080```, ```https://opencti.example.com``` |
| OPENCTI_TOKEN | `string` | ✅ | Length: `string >= 1` |  | Authentication token for accessing the OpenCTI API |  |
| GTI_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key for authenticating with the Google Threat Intelligence service |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` | Type of connector - must be EXTERNAL_IMPORT for import connectors |  |
| CONNECTOR_NAME | `string` |  | Length: `string >= 1` | `"Google Threat Intel Feeds"` | Display name for the connector |  |
| CONNECTOR_SCOPE | `string` |  | string | `"report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability,campaign"` | Comma-separated list of OpenCTI entity types that this connector can import |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Logging level for the connector |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT2H"` | ISO 8601 duration between connector runs (e.g., PT2H for 2 hours) |  |
| CONNECTOR_QUEUE_THRESHOLD | `integer` |  | `1 <= x ` | `500` | Maximum number of messages in the connector queue before throttling |  |
| CONNECTOR_TLP_LEVEL | `string` |  | `WHITE` `GREEN` `AMBER` `RED` `WHITE+STRICT` `GREEN+STRICT` `AMBER+STRICT` `RED+STRICT` | `"AMBER+STRICT"` | Traffic Light Protocol (TLP) marking for imported data |  |
| GTI_API_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://www.virustotal.com/api/v3"` | Base URL for the Google Threat Intelligence API |  |
| GTI_CAMPAIGN_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import campaigns (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_CAMPAIGNS | `boolean` |  | boolean | `false` | Whether to enable importing campaign data from GTI |  |
| GTI_CAMPAIGN_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of campaign origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner,google threat intelligence```, ```crowdsourced``` |
| GTI_VULNERABILITY_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import vulnerabilities (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `false` | Whether to enable importing vulnerability data from GTI |  |
| GTI_VULNERABILITY_GET_RELATED_SOFTWARES | `boolean` |  | boolean | `false` | Whether to enable importing related software data from vulnerability data |  |
| GTI_VULNERABILITY_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of vulnerability origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner,google threat intelligence```, ```crowdsourced``` |
| GTI_MALWARE_FAMILY_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import malware families (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_MALWARE_FAMILIES | `boolean` |  | boolean | `false` | Whether to enable importing malware family data from GTI |  |
| GTI_MALWARE_FAMILY_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of malware family origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner,google threat intelligence```, ```crowdsourced``` |
| GTI_ENABLE_MALWARE_ALIASES | `boolean` |  | boolean | `false` | Whether to enable importing malware family aliases from GTI |  |
| GTI_THREAT_ACTOR_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import threat actors (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_THREAT_ACTORS | `boolean` |  | boolean | `false` | Whether to enable importing threat actor data from GTI |  |
| GTI_THREAT_ACTOR_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of threat actor origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner,google threat intelligence```, ```crowdsourced``` |
| GTI_ENABLE_THREAT_ACTOR_ALIASES | `boolean` |  | boolean | `false` | Whether to enable importing threat actor aliases from GTI |  |
| GTI_REPORT_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import reports (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Whether to enable importing report data from GTI |  |
| GTI_REPORT_TYPES | `array` |  | string | `["All"]` | Comma-separated list of report types to import, or 'All' for all types. Allowed values: All, Actor Profile, Country Profile, Cyber Physical Security Roundup, Event Coverage/Implication, Industry Reporting, Malware Profile, Net Assessment, Network Activity Reports, News Analysis, OSINT Article, Patch Report, Strategic Perspective, TTP Deep Dive, Threat Activity Alert, Threat Activity Report, Trends and Forecasting, Weekly Vulnerability Exploitation Report | ```All```, ```Actor Profile,Malware Profile```, ```Threat Activity Alert``` |
| GTI_REPORT_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of report origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner,google threat intelligence```, ```crowdsourced``` |
