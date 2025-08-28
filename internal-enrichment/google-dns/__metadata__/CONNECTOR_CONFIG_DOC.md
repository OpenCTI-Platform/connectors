# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token of the user who represents the connector in the OpenCTI platform. |
| CONNECTOR_ID | `string` |  | string | `"googledns--0c1ac73d-f173-4349-9580-322c22fa7768"` | A unique UUIDv4 identifier for this connector instance. |
| CONNECTOR_NAME | `string` |  | string | `"Google DNS"` | Name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"Domain-Name,Hostname"` | The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only). |
| CONNECTOR_TYPE | `string` |  | string | `"INTERNAL_ENRICHMENT"` | Should always be set to INTERNAL_ENRICHMENT for this connector. |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Enables or disables automatic enrichment of observables for OpenCTI. |
| CONNECTOR_CONFIDENCE_LEVEL | `integer` |  | integer | `100` | The default confidence level (a number between 1 and 100). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `error` | `"error"` | Determines the verbosity of the logs. |
| CONNECTOR_LISTEN_PROTOCOL | `string` |  | string | `null` | Protocol used for listening. |
| CONNECTOR_LISTEN_PROTOCOL_API_PORT | `integer` |  | integer | `null` | Port used for API listening. |
| CONNECTOR_LISTEN_PROTOCOL_API_PATH | `string` |  | string | `null` | API path for callback. |
| CONNECTOR_LISTEN_PROTOCOL_API_URI | `string` |  | string | `null` | Full URI for API listening. |
| CONNECTOR_LISTEN_PROTOCOL_API_SSL | `boolean` |  | boolean | `null` | Enable SSL for API listening. |
| CONNECTOR_LISTEN_PROTOCOL_API_SSL_KEY | `string` |  | string | `null` | SSL key file path. |
| CONNECTOR_LISTEN_PROTOCOL_API_SSL_CERT | `string` |  | string | `null` | SSL certificate file path. |
