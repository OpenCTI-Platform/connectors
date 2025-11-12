# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| VIRUSTOTAL_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | VirusTotal API token for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"VirusTotal"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile", "Artifact", "IPv4-Addr", "Domain-Name", "Url", "Hostname"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables for OpenCTI. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| VIRUSTOTAL_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. Available values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED |
| VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE | `boolean` |  | boolean | `true` | Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true). |
| VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT | `boolean` |  | boolean | `true` | Whether or not to include the full report as a Note. |
| VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS | `boolean` |  | boolean | `true` | Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis. |
| VIRUSTOTAL_FILE_IMPORT_YARA | `boolean` |  | boolean | `true` | Whether or not to import Crowdsourced YARA rules. |
| VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for File/Artifact based observables once this positive threshold is reached. |
| VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |
| VIRUSTOTAL_FILE_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |
| VIRUSTOTAL_IP_ADD_RELATIONSHIPS | `boolean` |  | boolean | `false` | Whether or not to add ASN and location resolution relationships. |
| VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for IPv4 based observables once this positive threshold is reached. |
| VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |
| VIRUSTOTAL_IP_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |
| VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS | `boolean` |  | boolean | `false` | Whether or not to add IP resolution relationships. |
| VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for Domain based observables once this positive threshold is reached. |
| VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |
| VIRUSTOTAL_DOMAIN_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |
| VIRUSTOTAL_URL_UPLOAD_UNSEEN | `boolean` |  | boolean | `true` | Whether to upload URLs that VirusTotal has no record of for analysis. |
| VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES | `integer` |  | integer | `10` | Create an indicator for URL based observables once this positive threshold is reached. |
| VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES | `integer` |  | integer | `2880` | How long the indicator is valid for in minutes. |
| VIRUSTOTAL_URL_INDICATOR_DETECT | `boolean` |  | boolean | `true` | Whether or not to set detection for the indicator to true. |
| VIRUSTOTAL_INCLUDE_ATTRIBUTES_IN_NOTE | `boolean` |  | boolean | `false` | Whether or not to include the attributes info in Note. |
