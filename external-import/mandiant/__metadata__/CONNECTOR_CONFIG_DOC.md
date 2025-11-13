# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| MANDIANT_API_V4_KEY_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Mandiant API v4 Key ID for authentication. |
| MANDIANT_API_V4_KEY_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Mandiant API v4 Key Secret for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"Mandiant"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["mandiant"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. Options are debug, info, warn, warning or error. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT5M"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| MANDIANT_MARKING | `string` |  | `white` `clear` `green` `amber` `amber+strict` `red` | `"amber+strict"` | TLP Marking for data imported, possible values: white, clear, green, amber, amber+strict, red. NB: Some of the entities retrieved from the Mandiant portal already have a marking. We do not modify the marking on these entities. The marking defined by this parameter only takes into account entities created by the connector, or entities retrieved without marking. |
| MANDIANT_REMOVE_STATEMENT_MARKING | `boolean` |  | boolean | `false` | Whether to remove statement markings from imported data. |
| MANDIANT_CREATE_NOTES | `boolean` |  | boolean | `false` | Whether to create notes from imported data. |
| MANDIANT_IMPORT_START_DATE | `string` |  | string |  | Date to start collect data (Format: YYYY-MM-DD). Defaults to 30 days ago before first run the connector. |
| MANDIANT_IMPORT_PERIOD | `integer` |  | `0 < x ` | `1` | Number of days to fetch in one round trip. |
| MANDIANT_INDICATOR_IMPORT_START_DATE | `string` |  | string |  | Date to start collect indicators (Format: YYYY-MM-DD). Defaults to 30 days ago before first run the connector. |
| MANDIANT_INDICATOR_MINIMUM_SCORE | `integer` |  | `0 < x ` | `80` | Minimum score (based on mscore) that an indicator must have to be processed. |
| MANDIANT_IMPORT_INDICATORS | `boolean` |  | boolean | `true` | Enable to collect indicators. |
| MANDIANT_IMPORT_INDICATORS_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new indicators. |
| MANDIANT_IMPORT_ACTORS | `boolean` |  | boolean | `true` | Enable to collect actors. |
| MANDIANT_IMPORT_ACTORS_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new actors. |
| MANDIANT_IMPORT_ACTORS_ALIASES | `boolean` |  | boolean | `false` | Import actors aliases. |
| MANDIANT_IMPORT_MALWARES | `boolean` |  | boolean | `true` | Enable to collect malwares. |
| MANDIANT_IMPORT_MALWARES_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new malwares. |
| MANDIANT_IMPORT_MALWARES_ALIASES | `boolean` |  | boolean | `false` | Import malwares aliases. |
| MANDIANT_IMPORT_CAMPAIGNS | `boolean` |  | boolean | `true` | Enable to collect campaigns. |
| MANDIANT_IMPORT_CAMPAIGNS_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new campaigns. |
| MANDIANT_IMPORT_INDICATORS_WITH_FULL_CAMPAIGNS | `boolean` |  | boolean | `false` | Enable to collect campaigns with related entities when importing IOC linked to this campaign. |
| MANDIANT_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `false` | Enable to collect vulnerabilities. |
| MANDIANT_IMPORT_VULNERABILITIES_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new vulnerabilities. |
| MANDIANT_IMPORT_REPORTS | `boolean` |  | boolean | `true` | Enable to collect reports. |
| MANDIANT_IMPORT_REPORTS_INTERVAL | `integer` |  | `0 < x ` | `1` | Interval in hours to check and collect new reports. |
| MANDIANT_ACTOR_PROFILE_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'actor_profile'. |
| MANDIANT_ACTOR_PROFILE_REPORT_TYPE | `string` |  | string | `"actor-profile"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_COUNTRY_PROFILE_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'country_profile'. |
| MANDIANT_COUNTRY_PROFILE_REPORT_TYPE | `string` |  | string | `"country-profile"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'event_coverage_implication'. |
| MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT_TYPE | `string` |  | string | `"event-coverage"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'executive_perspective'. |
| MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT_TYPE | `string` |  | string | `"executive-perspective"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_ICS_SECURITY_ROUNDUP_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'ics_security_roundup'. |
| MANDIANT_ICS_SECURITY_ROUNDUP_REPORT_TYPE | `string` |  | string | `"ics-security-roundup"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_INDUSTRY_REPORTING_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'industry_reporting'. |
| MANDIANT_INDUSTRY_REPORTING_REPORT_TYPE | `string` |  | string | `"industry"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_MALWARE_PROFILE_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'malware_profile'. |
| MANDIANT_MALWARE_PROFILE_REPORT_TYPE | `string` |  | string | `"malware-profile"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_NETWORK_ACTIVITY_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'network_activity_reports'. |
| MANDIANT_NETWORK_ACTIVITY_REPORT_TYPE | `string` |  | string | `"network-activity"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_PATCH_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'patch_report'. |
| MANDIANT_PATCH_REPORT_TYPE | `string` |  | string | `"patch"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_TTP_DEEP_DIVE_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'ttp_deep_dive'. |
| MANDIANT_TTP_DEEP_DIVE_REPORT_TYPE | `string` |  | string | `"ttp-deep-dive"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_THREAT_ACTIVITY_ALERT_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'news_analysis'. |
| MANDIANT_THREAT_ACTIVITY_ALERT_REPORT_TYPE | `string` |  | string | `"threat-alert"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_THREAT_ACTIVITY_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'threat_activity_report'. |
| MANDIANT_THREAT_ACTIVITY_REPORT_TYPE | `string` |  | string | `"threat-activity"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_TRENDS_AND_FORECASTING_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'trends_and_forecasting'. |
| MANDIANT_TRENDS_AND_FORECASTING_REPORT_TYPE | `string` |  | string | `"trends-forecasting"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_VULNERABILITY_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'vulnerability_report'. |
| MANDIANT_VULNERABILITY_REPORT_TYPE | `string` |  | string | `"vulnerability"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_VULNERABILITY_IMPORT_SOFTWARE_CPE | `boolean` |  | boolean | `true` | Enable to import CPE and version or not. |
| MANDIANT_VULNERABILITY_MAX_CPE_RELATIONSHIP | `integer` |  | `0 < x ` | `200` | Enable to define a maximum number of relationships created for a vulnerability. |
| MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'weekly_vulnerability_exploitation_report'. |
| MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT_TYPE | `string` |  | string | `"vulnerability-exploitation"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_NEWS_ANALYSIS_REPORT | `boolean` |  | boolean | `true` | Enable to collect report type 'news_analysis'. |
| MANDIANT_NEWS_ANALYSIS_REPORT_TYPE | `string` |  | string | `"news-analysis"` | Report type on vocabulary 'report_types_ov'. |
| MANDIANT_GUESS_RELATIONSHIPS_REPORTS | `string` |  | string | `"Actor Profile, Malware Profile, Vulnerability Report"` | Enable the capability to guess the relationships in selected reports type. Valid values: 'All, None, Actor Profile, Country Profile, Event Coverage/Implication, Executive Perspective, ICS Security Roundup, Industry Reporting, Malware Profile, Network Activity Reports, Patch Report, TTP Deep Dive, Threat Activity Alert, Threat Activity Report, Trends and Forecasting, Vulnerability Report, Weekly Vulnerability Exploitation Report, News Analysis'. Multiple values can be given in a string comma separated. If All or None is in the string it will override any other values. None is used before All. |
