# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CYBELANGEL_CLIENT_ID | `string` | ✅ | string |  | CybelAngel OAuth2 client ID. |
| CYBELANGEL_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | CybelAngel OAuth2 client secret. |
| CONNECTOR_NAME | `string` |  | string | `"CybelAngel"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | The period of time to await between two runs of the connector. |
| CYBELANGEL_API_URL | `string` |  | string | `"https://platform.cybelangel.com"` | CybelAngel platform API base URL. |
| CYBELANGEL_AUTH_URL | `string` |  | string | `"https://auth.cybelangel.com/oauth/token"` | CybelAngel OAuth2 token endpoint URL. |
| CYBELANGEL_AUDIENCE | `string` |  | string | `null` | OAuth2 audience claim. Defaults to api_url with a trailing slash when not set. |
| CYBELANGEL_MARKING | `string` |  | string | `"TLP:AMBER+STRICT"` | TLP marking to apply to imported objects. Accepted values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED. |
| CYBELANGEL_FETCH_PERIOD | `string` |  | string | `"7"` | Number of days to look back on the first run. Use "all" to fetch all available data. |
