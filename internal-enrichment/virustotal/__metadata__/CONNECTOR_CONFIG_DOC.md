# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |  |
| OPENCTI_TOKEN | `string` | ✅ | Length: `string >= 1` |  | The token of the user who represents the connector in the OpenCTI platform. |  |
| VIRUSTOTAL_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | VirusTotal API token for authentication. |  |
| CONNECTOR_NAME | `string` |  | Length: `string >= 1` | `"VirusTotal"` | Name of the connector. |  |
| CONNECTOR_SCOPE | `array` |  | Length: `string >= 1` | `["StixFile", "Artifact", "IPv4-Addr", "Domain-Name", "Url", "Hostname", "Indicator"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |  |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables for OpenCTI. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |  |
| VIRUSTOTAL_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. Available values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED |  |
| VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean | `true` | Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true). |  |
| VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT | `boolean` |  | boolean | `true` | Whether or not to include the full report as a Note. |  |
| VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS | `boolean` |  | boolean | `true` | Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis. |  |
| VIRUSTOTAL_FILE_IMPORT_YARA | `boolean` |  | boolean | `true` | Whether or not to import Crowdsourced YARA rules. |  |
| VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for File/Artifact based observables once this positive threshold is reached. |  |
| VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |  |
| VIRUSTOTAL_FILE_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |  |
| VIRUSTOTAL_IP_ADD_RELATIONSHIPS | `boolean` |  | boolean | `false` | Whether or not to add ASN and location resolution relationships. |  |
| VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for IPv4 based observables once this positive threshold is reached. |  |
| VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |  |
| VIRUSTOTAL_IP_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |  |
| VIRUSTOTAL_IP_ADD_RESOLUTIONS | `boolean` |  | boolean | `false` | Whether or not to import the domains resolving to the IP (VirusTotal resolutions) as Domain-Name observables linked with a dated `resolves-to` relationship. Off: no additional API call and no additional object. |  |
| VIRUSTOTAL_IP_RESOLUTIONS_SINCE | `string` |  | string | `"P90D"` | Date floor for IP resolutions: stop paging at the first resolution last seen before it. ISO-8601 duration relative to each enrichment (`P90D`), absolute ISO-8601 date (`2025-10-01`) or `none` to disable the floor (the entry and page caps still apply). | ```P90D```, ```2025-10-01```, ```none``` |
| VIRUSTOTAL_IP_RESOLUTIONS_MAX_ENTRIES | `integer` |  | `1 <= x ` | `null` | Entry cap for IP resolutions: stop after this many resolutions fetched per enrichment, newest first, counted before the keyword filter. Sent to VirusTotal as the page size when below 40. Unset: no entry cap. | ```3``` |
| VIRUSTOTAL_IP_RESOLUTIONS_MAX_PAGES | `integer` |  | `1 <= x ` | `25` | Safety cap for IP resolutions: maximum number of pages (40 entries, one API lookup each) fetched per enrichment, whatever the date floor says. | ```25``` |
| VIRUSTOTAL_IP_RESOLUTIONS_KEYWORDS_REGEX | `string` |  | Length: `string >= 1` | `null` | Case-insensitive regular expression a resolved domain must match to be imported. Filters the created objects, not the API quota. Unset: import all resolved domains. | ```^news```, ```press``` |
| VIRUSTOTAL_API_REQUESTS_PER_MINUTE | `integer` |  | `0 <= x ` | `4` | Spacing between IP resolutions pages, in requests per minute. 4 fits a free API key; 0 disables the wait (premium keys). Applies only to IP resolutions paging. | ```4```, ```0``` |
| VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS | `boolean` |  | boolean | `false` | Whether or not to add IP resolution relationships. |  |
| VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for Domain based observables once this positive threshold is reached. |  |
| VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |  |
| VIRUSTOTAL_DOMAIN_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |  |
| VIRUSTOTAL_URL_UPLOAD_UNSEEN | `boolean` |  | boolean | `true` | Whether to upload URLs that VirusTotal has no record of for analysis. |  |
| VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for URL based observables once this positive threshold is reached. |  |
| VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |  |
| VIRUSTOTAL_URL_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |  |
| VIRUSTOTAL_INCLUDE_ATTRIBUTES_IN_NOTE | `boolean` |  | boolean | `false` | Whether or not to include the attributes info in Note. |  |
| VIRUSTOTAL_GTI_ENRICHMENT_ENABLED | `boolean` |  | boolean | `false` | Whether to use GTI assessment data (score/verdict) and enable GTI relationship enrichment. Requires a VirusTotal account with GTI access. |  |
| VIRUSTOTAL_GTI_INCLUDE_MALWARE_FAMILIES | `boolean` |  | boolean | `false` | Whether or not to enrich with related GTI malware families (created as Malware entities). |  |
| VIRUSTOTAL_GTI_INCLUDE_THREAT_ACTORS | `boolean` |  | boolean | `false` | Whether or not to enrich with related GTI threat actors (created as Intrusion-Set entities). |  |
| VIRUSTOTAL_GTI_INCLUDE_CAMPAIGNS | `boolean` |  | boolean | `false` | Whether or not to enrich with related GTI campaigns (created as Campaign entities). |  |
| VIRUSTOTAL_GTI_INCLUDE_REPORTS | `boolean` |  | boolean | `false` | Whether or not to enrich with related GTI reports (created as Report entities). |  |
| VIRUSTOTAL_GTI_RELATIONSHIP_LIMIT | `integer` |  | `0 < x ` | `10` | Maximum number of related objects to pull per GTI relationship, per observable. |  |
