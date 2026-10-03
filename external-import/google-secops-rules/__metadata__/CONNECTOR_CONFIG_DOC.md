# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| GOOGLE_SECOPS_RULES_PROJECT_ID | `string` | ✅ | Length: `string >= 1` |  | Google Cloud project bound to the Google SecOps instance (project id or number). |
| GOOGLE_SECOPS_RULES_PROJECT_REGION | `string` | ✅ | [`^[a-z0-9-]+$`](https://regex101.com/?regex=%5E%5Ba-z0-9-%5D%2B%24) |  | Region of the Google SecOps instance, e.g. `us`, `europe`, `europe-west2` or `asia-southeast1`. |
| GOOGLE_SECOPS_RULES_PROJECT_INSTANCE | `string` | ✅ | Length: `string >= 1` |  | Google SecOps instance (customer) id, a UUID shown in **SIEM Settings -> Profile**. |
| GOOGLE_SECOPS_RULES_CLIENT_EMAIL | `string` | ✅ | Length: `string >= 1` |  | Email of the service account. It needs the `Chronicle API Viewer` role (`roles/chronicle.viewer`) on the project. |
| GOOGLE_SECOPS_RULES_PRIVATE_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Private key of the service account (PEM, the `private_key` of its JSON key file). Literal `\n` sequences are turned into line breaks. |
| CONNECTOR_NAME | `string` |  | string | `"Google SecOps Detection Rules"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Indicator", "Attack-Pattern", "SecurityPlatform"]` | The scope of the connector, i.e. the entity types it imports. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT6H` for six hours). Every run reads the full rule set. |
| GOOGLE_SECOPS_RULES_PRIVATE_KEY_ID | `string` |  | string | `null` | Id of that private key (the `private_key_id` of the JSON key file). |
| GOOGLE_SECOPS_RULES_TOKEN_URI | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://oauth2.googleapis.com/token"` | OAuth 2.0 token endpoint of the service account. |
| GOOGLE_SECOPS_RULES_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://chronicle.googleapis.com/"` | Chronicle API endpoint. The region is prefixed to its host at runtime (`https://<region>-chronicle.googleapis.com`). |
| GOOGLE_SECOPS_RULES_API_VERSION | `string` |  | `v1` `v1beta` `v1alpha` | `"v1alpha"` | Chronicle API version serving the rules and rule deployments. |
| GOOGLE_SECOPS_RULES_IMPORT_DISABLED_RULES | `boolean` |  | boolean | `true` | Import rules that are not live too, with the deployment status `deployed` (live rules get `active`). When false, they are left out and count as removed. |
| GOOGLE_SECOPS_RULES_PAGE_SIZE | `integer` |  | `1 <= x <= 1000` | `1000` | Rules and rule deployments requested per page. |
| GOOGLE_SECOPS_RULES_REQUEST_TIMEOUT | `integer` |  | `1 <= x ` | `60` | Timeout of each HTTP request, in seconds. |
| GOOGLE_SECOPS_RULES_MAX_RETRIES | `integer` |  | `0 <= x ` | `5` | Retries of a request failing with a rate limit (429), a server error (5xx) or a network error, with exponential backoff. |
| GOOGLE_SECOPS_RULES_PLATFORM_NAME | `string` |  | Length: `string >= 1` | `"Google SecOps"` | Name of the Security Platform the rules are deployed on in OpenCTI. |
| GOOGLE_SECOPS_RULES_PLATFORM_TYPE | `string` |  | `SIEM` `EDR` `XDR` `SOAR` `NDR` `ISPM` | `"SIEM"` | Type of that Security Platform (`security_platform_type`). |
| GOOGLE_SECOPS_RULES_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | TLP marking applied to every object this connector creates. |
