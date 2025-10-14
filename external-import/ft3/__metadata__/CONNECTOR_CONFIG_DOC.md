# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"FT3 Framework"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["identity", "attack-pattern", "x-mitre-tactic", "x-opencti-kill-chain", "marking-definition"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| FT3_INTERVAL | `integer` |  | `0 < x ` | `5` | Polling interval in days for fetching and refreshing FT3 data. Determines how often the system checks for updates to FT3 datasets. |
| FT3_TACTICS_URL | `string` |  | string | `"https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Tactics.json"` | URL to the FT3 Tactics JSON file. This dataset includes fraud tactics from the FT3 framework. |
| FT3_TECHNIQUES_URL | `string` |  | string | `"https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Techniques.json"` | URL to the FT3 Techniques JSON file. Contains fraud techniques and their relationships to tactics. |
