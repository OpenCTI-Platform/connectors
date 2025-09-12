# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| SEKOIA_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API key used to authenticate requests to the Sekoia service. |
| CONNECTOR_NAME | `string` |  | string | `"SEKOIA.IO"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report,location,vulnerability,indicator,campaign,infrastructure,relationship"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"EXTERNAL_IMPORT"` | Should always be set to EXTERNAL_IMPORT for this connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT60S"` | Duration between two scheduled runs of the connector (ISO 8601 format). |
| SEKOIA_BASE_URL | `string` |  | string | `"https://api.sekoia.io"` | Base URL for accessing the Sekoia API. |
| SEKOIA_COLLECTION | `string` |  | string | `"d6092c37-d8d7-45c3-8aff-c4dc26030608"` | Allows you to specify the collection to query in order to retrieve or manage indicators of compromise. |
| SEKOIA_START_DATE | `string` |  | string | `null` | The date to start consuming data from. May be in the formats YYYY-MM-DD or YYYY-MM-DDT00:00:00. |
| SEKOIA_LIMIT | `integer` |  | `0 < x ` | `200` | The number of elements to fetch in each request. Defaults to 200, maximum 2000. |
| SEKOIA_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Create observables from indicators. |
| SEKOIA_IMPORT_SOURCE_LIST | `boolean` |  | boolean | `false` | Create the list of sources observed by Sekoia as label. |
| SEKOIA_IMPORT_IOC_RELATIONSHIPS | `boolean` |  | boolean | `true` | Import IOCs relationships and related objects. |
