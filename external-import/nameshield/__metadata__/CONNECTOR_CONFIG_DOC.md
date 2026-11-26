# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| NAMESHIELD_AUTH_BEARER | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Bearer token of the NameShield API. The IP address of the connector must also be allowed on the NameShield side. |
| CONNECTOR_NAME | `string` |  | string |  | `"NameShield"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["NameShield"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"P7D"` | The period of time to await between two runs of the connector. |
| NAMESHIELD_SERVER | `string` |  | string |  | `"api.nameshield.net"` | NameShield API server, used as `{server}` in the URL templates. |
| NAMESHIELD_API_VERSION | `string` |  | string |  | `"v1"` | NameShield API version, used as `{api_version}` in the URL templates. |
| NAMESHIELD_API_ENDPOINT | `string` |  | string |  | `"registrar"` | NameShield API endpoint, used as `{api_endpoint}` in the URL templates. |
| NAMESHIELD_URL_LIST | `string` |  | string |  | `"https://{server}/{api_endpoint}/{api_version}/domains"` | URL template of the domain list. Supports the `{server}`, `{api_endpoint}` and `{api_version}` placeholders. |
| NAMESHIELD_URL_DOMAIN | `string` |  | string |  | `"https://{server}/{api_endpoint}/{api_version}/domains/{domain}"` | URL template of the domain details. Supports the `{server}`, `{api_endpoint}`, `{api_version}` and `{domain}` placeholders. |
| NAMESHIELD_DOMAIN_LIMIT | `integer` |  | integer |  | `10000` | Maximum number of domains imported per run. |
| NAMESHIELD_MARKING | `string` |  | string |  | `"TLP:GREEN"` | TLP marking applied to the imported objects: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` or `TLP:RED`. Any other value falls back to `TLP:AMBER+STRICT`. |
| NAMESHIELD_LINK_TO_IDENTITIES | `string` |  | string |  | `""` | Comma-separated STIX IDs of identities (for example your organization) the indicators are attributed to. Leave empty to create no link. |
| NAMESHIELD_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| NAMESHIELD_MARKING_DEFINITION | `string` |  | string | ⛔️ | `null` | Use NAMESHIELD_MARKING instead. |
