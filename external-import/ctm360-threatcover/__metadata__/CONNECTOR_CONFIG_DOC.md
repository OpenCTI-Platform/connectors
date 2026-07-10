# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CTM360_THREATCOVER_DISCOVERY_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CTM360 ThreatCover TAXII discovery URL (e.g. https://<tenant>.ctm360.com/taxii2/). |
| CTM360_THREATCOVER_COLLECTION | `string` | ✅ | string |  | TAXII collection to poll (the ThreatCover 'Observables' collection id or title). |
| CONNECTOR_NAME | `string` |  | string | `"CTM360 ThreatCover"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | The period of time to await between two runs of the connector. |
| CTM360_THREATCOVER_V21 | `boolean` |  | boolean | `true` | Use TAXII 2.1 (set to false for a TAXII 2.0 server). |
| CTM360_THREATCOVER_USE_TOKEN | `boolean` |  | boolean | `true` | Authenticate with a token (Authorization header). Default for CTM360 ThreatCover. |
| CTM360_THREATCOVER_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | CTM360 ThreatCover API token (used when use_token is true). |
| CTM360_THREATCOVER_USE_APIKEY | `boolean` |  | boolean | `false` | Authenticate with a custom API-key header instead of a token. |
| CTM360_THREATCOVER_APIKEY_KEY | `string` |  | string | `null` | Header name to use when use_apikey is true. |
| CTM360_THREATCOVER_APIKEY_VALUE | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Header value to use when use_apikey is true. |
| CTM360_THREATCOVER_USERNAME | `string` |  | string | `null` | Username for HTTP basic authentication (when neither token nor apikey is used). |
| CTM360_THREATCOVER_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Password for HTTP basic authentication. |
| CTM360_THREATCOVER_CERT_PATH | `string` |  | string | `null` | Optional path to a client certificate for mutual TLS. |
| CTM360_THREATCOVER_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TAXII server TLS certificate. |
| CTM360_THREATCOVER_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | Default TLP marking applied to the imported entities. |
