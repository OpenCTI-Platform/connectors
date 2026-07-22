# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| GREYNOISE_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The GreyNoise API key. |
| CONNECTOR_NAME | `string` |  | string | `"Greynoise"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["IPv4-Addr"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| GREYNOISE_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP level for data to be sent to GreyNoise. |
| GREYNOISE_SIGHTING_NOT_SEEN | `boolean` |  | boolean | `false` | Create sighting with count=0 when IP not seen. |
| GREYNOISE_NO_SIGHTINGS | `boolean` |  | boolean | `false` | Skip any sighting creations. |
| GREYNOISE_NAME | `string` |  | string | `"GreyNoise Intelligence"` | The name of the GreyNoise identity created in OpenCTI. |
| GREYNOISE_DESCRIPTION | `string` |  | string | `"GreyNoise collects and analyzes untargeted, widespread, and opportunistic scan and attack activity that reaches every server directly connected to the Internet."` | The description of the GreyNoise identity created in OpenCTI. |
| GREYNOISE_INDICATOR_SCORE_MALICIOUS | `integer` |  | integer | `75` | The `x_opencti_score` value to set on indicators classified as malicious. |
| GREYNOISE_INDICATOR_SCORE_SUSPICIOUS | `integer` |  | integer | `50` | The `x_opencti_score` value to set on indicators classified as suspicious. |
| GREYNOISE_INDICATOR_SCORE_BENIGN | `integer` |  | integer | `20` | The `x_opencti_score` value to set on indicators classified as benign. |
