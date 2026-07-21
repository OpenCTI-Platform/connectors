# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_NAME | `string` |  | string | `"Ransomware Connector"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["identity", "attack-pattern", "course-of-action", "intrusion-set", "malware", "tool", "report"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT10M"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| CONNECTOR_PULL_HISTORY | `boolean` |  | boolean | `false` | Whether to pull historic data. It is not recommended to set it to ``true`` as there will be a large influx of data. |
| CONNECTOR_HISTORY_START_YEAR | `integer` |  | `0 < x ` | `2023` | Year (or ``YYYYMM``) to start the historical backfill from. Accepts the four-digit year shape (``2023``) — backfill begins on January 1st of that year — or the six-digit year-month shape (``202306``) — backfill begins on the first of that month. The ransomware.live feed only goes back to 2020; values older than 2020 are clamped to ``2020-01`` at runtime. |
| CONNECTOR_CREATE_THREAT_ACTOR | `boolean` |  | boolean | `false` | Whether to create a Threat Actor object. |
| CONNECTOR_CREATE_INTRUSION_SET | `boolean` |  | boolean | `true` | Whether to create an Intrusion Set object. |
| CONNECTOR_CREATE_CAMPAIGN | `boolean` |  | boolean | `false` | Whether to create a Campaign object. |
| CONNECTOR_CREATE_REPORT | `boolean` |  | boolean | `true` | Whether to create a Report object. |
| CONNECTOR_MARKING_VALUE | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:CLEAR"` | TLP marking attached to every emitted STIX object. ``TLP:CLEAR`` (default) is the OpenCTI-specific modern label; ``TLP:WHITE`` is the legacy STIX 2.1 equivalent. |
| CONNECTOR_CREATE_LEAK_SITE_DOMAINS | `boolean` |  | boolean | `false` | Whether to create DomainName observables for ransomware group leak sites and link them to the IntrusionSet |
| CONNECTOR_CREATE_LEAK_POST_REFS | `boolean` |  | boolean | `false` | Whether to include the leak post URL as an external reference on victim reports |
