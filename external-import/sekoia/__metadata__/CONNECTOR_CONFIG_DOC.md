# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| SEKOIA_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate requests to the Sekoia service. |
| CONNECTOR_NAME | `string` |  | string | `"SEKOIA.IO"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["identity", "attack-pattern", "course-of-action", "intrusion-set", "malware", "tool", "report", "location", "vulnerability", "indicator", "campaign", "infrastructure", "relationship"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1M"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| SEKOIA_BASE_URL | `string` |  | string | `"https://api.sekoia.io"` | Base URL for accessing the Sekoia API. |
| SEKOIA_COLLECTION | `string` |  | string | `"d6092c37-d8d7-45c3-8aff-c4dc26030608"` | Allows you to specify the collection to query in order to retrieve or manage indicators of compromise. |
| SEKOIA_START_DATE | `string` |  | string | `null` | The date to start consuming data from. May be in the formats YYYY-MM-DD or YYYY-MM-DDT00:00:00. |
| SEKOIA_LIMIT | `integer` |  | `0 < x ` | `200` | The number of elements to fetch in each request. Defaults to 200, maximum 2000. |
| SEKOIA_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create observables from indicators. |
| SEKOIA_IMPORT_SOURCE_LIST | `boolean` |  | boolean | `false` | Create the list of sources observed by Sekoia as label. |
| SEKOIA_IMPORT_IOC_RELATIONSHIPS | `boolean` |  | boolean | `true` | Import IOCs relationships and related objects. |
| SEKOIA_CONFIDENCE_SCORE | `integer` |  | integer | `null` | This will be the score assigned to the indicators. Defaults to null, maximum 100. |
| SEKOIA_SEND_CONFIDENCE | `boolean` |  | boolean | `true` | Whether to include Sekoia's native STIX confidence property on objects in the bundle sent. |
| SEKOIA_MAX_EXTERNAL_REFERENCES | `integer` |  | `0 < x ` | `null` | Maximum number of external references kept on each object (for example 50). The Sekoia.io reference is always kept and counts toward the limit. Defaults to no limit. |
