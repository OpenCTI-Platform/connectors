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
| GTI_SOFTWARE_TOOLKIT_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import software toolkits (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_SOFTWARE_TOOLKITS | `boolean` |  | boolean | `false` | Whether to enable importing software toolkit data from GTI |  |
| GTI_SOFTWARE_TOOLKIT_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of software toolkit origins to import, or 'All' for all origins. Allowed values: All, partner, google threat intelligence | ```All```, ```partner```, ```google threat intelligence``` |
| GTI_SOFTWARE_TOOLKIT_EXTRA_FILTERS | `array` |  | string | `[]` | Optional list of additional filters to add to query when fetching software toolkits | ```name:Cobalt Strike``` |
| GTI_IMPORT_INDICATORS | `boolean` |  | boolean | `false` | Whether to enable importing IOC indicator data from GTI via Steady-State IOC Deltas API |  |
| GTI_INDICATOR_TYPES | `array` |  | string | `["file", "ip", "url", "domain"]` | Comma-separated list of IOC types to import. Allowed: file, ip, url, domain |  |
| GTI_INDICATOR_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import indicators on first run (e.g. P1D for 1 day, P7D for 7 days). Must be greater than 1 hour (the IOC delta package granularity). |  |
| GTI_INDICATOR_MIN_SCORE | `integer` |  | `0 <= x <= 100` | `50` | Minimum GTI score (0-100) an indicator must have to be imported via the Steady-State IOC Deltas API. Indicators with a lower score are discarded. Indicators without a score are always imported. Set to 100 or leave unset (None) to disable the filter entirely. |  |
| GTI_CAMPAIGN_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import campaigns (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_CAMPAIGNS | `boolean` |  | boolean | `false` | Whether to enable importing campaign data from GTI |  |
| GTI_CAMPAIGN_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of campaign origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner```, ```google threat intelligence```, ```crowdsourced``` |
| GTI_CAMPAIGN_EXTRA_FILTERS | `array` |  | string | `[]` | Optional List of additional filters to add to query when fetching campaigns | ```name:Operation Shadow``` |
| GTI_VULNERABILITY_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import vulnerabilities (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `false` | Whether to enable importing vulnerability data from GTI |  |
| GTI_VULNERABILITY_GET_RELATED_SOFTWARES | `boolean` |  | boolean | `false` | Whether to enable importing related software data from vulnerability data |  |
| GTI_VULNERABILITY_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of vulnerability origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner```, ```google threat intelligence```, ```crowdsourced``` |
| GTI_VULNERABILITY_EXTRA_FILTERS | `array` |  | string | `[]` | Optional List of additional filters to add to query when fetching vulnerabilities. | ```name:CVE-2024``` |
| GTI_MALWARE_FAMILY_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import malware families (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_MALWARE_FAMILIES | `boolean` |  | boolean | `false` | Whether to enable importing malware family data from GTI |  |
| GTI_MALWARE_FAMILY_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of malware family origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner```, ```google threat intelligence```, ```crowdsourced``` |
| GTI_ENABLE_MALWARE_ALIASES | `boolean` |  | boolean | `false` | Whether to enable importing malware family aliases from GTI |  |
| GTI_MALWARE_FAMILY_EXTRA_FILTERS | `array` |  | string | `[]` | Optional List of additional filters to add to query when fetching malware families. | ```name:Emote``` |
| GTI_THREAT_ACTOR_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import threat actors (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_THREAT_ACTORS | `boolean` |  | boolean | `false` | Whether to enable importing threat actor data from GTI |  |
| GTI_THREAT_ACTOR_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of threat actor origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner```, ```google threat intelligence```, ```crowdsourced``` |
| GTI_ENABLE_THREAT_ACTOR_ALIASES | `boolean` |  | boolean | `false` | Whether to enable importing threat actor aliases from GTI |  |
| GTI_THREAT_ACTOR_EXTRA_FILTERS | `array` |  | string | `[]` | Optional List of additional filters to add to query when fetching threat actors. | ```name:APT28``` |
| GTI_REPORT_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P1D"` | ISO 8601 duration string specifying how far back to import reports (e.g., P1D for 1 day, P7D for 7 days) |  |
| GTI_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Whether to enable importing report data from GTI |  |
| GTI_REPORT_TYPES | `array` |  | string | `["All"]` | Comma-separated list of report types to import, or 'All' for all types. Allowed values: All, Actor Profile, Country Profile, Cyber Physical Security Roundup, Event Coverage/Implication, Industry Reporting, Malware Profile, Net Assessment, Network Activity Reports, News Analysis, OSINT Article, Patch Report, Strategic Perspective, TTP Deep Dive, Threat Activity Alert, Threat Activity Report, Trends and Forecasting, Weekly Vulnerability Exploitation Report | ```All```, ```Actor Profile,Malware Profile```, ```Threat Activity Alert``` |
| GTI_REPORT_DOWNLOAD_PDF | `boolean` |  | boolean | `false` | Whether to download report PDFs from the GTI API and attach them to the STIX Report objects in OpenCTI |  |
| GTI_REPORT_ORIGINS | `array` |  | string | `["google threat intelligence"]` | Comma-separated list of report origins to import, or 'All' for all origins. Allowed values: All, partner, crowdsourced, google threat intelligence | ```All```, ```partner```, ```google threat intelligence```, ```crowdsourced``` |
| GTI_REPORT_EXTRA_FILTERS | `array` |  | string | `[]` | Optional List of additional filters to add to query when fetching reports. | ```name:phishing``` |
