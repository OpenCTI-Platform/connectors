# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"Tagger"` | Name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["report", "malware", "tool"]` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `true` | If True, the connector will automatically import data from the API. |
| TAGGER_DEFINITIONS | `string` |  | string | `"[{\"scopes\":[\"Report\",\"Tool\"],\"rules\":[{\"label\":\"cloud\",\"search\":\"[Cc]loud\",\"attributes\":[\"name\",\"description\"]},{\"label\":\"mobile\",\"search\":\"mobile|android|apk\",\"flags\":[\"IGNORECASE\"],\"attributes\":[\"name\",\"description\"]}]},{\"scopes\":[\"Malware\"],\"rules\":[{\"label\":\"windows\",\"search\":\"registry|regkey\",\"flags\":[\"IGNORECASE\"],\"attributes\":[\"description\"]}]}]"` | Definitions array in JSON format |
