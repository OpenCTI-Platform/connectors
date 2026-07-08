# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| HATCHING_TRIAGE_SANDBOX_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Hatching Triage API token. See https://tria.ge/account |
| CONNECTOR_NAME | `string` |  | string | `"Hatching Triage Sandbox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact", "Url"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| HATCHING_TRIAGE_SANDBOX_BASE_URL | `string` |  | string | `"https://tria.ge/api"` | Hatching Triage API base URL. See https://tria.ge/docs/ |
| HATCHING_TRIAGE_SANDBOX_USE_EXISTING_ANALYSIS | `boolean` |  | boolean | `true` | If true, get existing analysis if any. |
| HATCHING_TRIAGE_SANDBOX_FAMILY_COLOR | `string` |  | string | `"#0059f7"` | Label color for malware family. |
| HATCHING_TRIAGE_SANDBOX_BOTNET_COLOR | `string` |  | string | `"#f79e00"` | Label color for botnet. |
| HATCHING_TRIAGE_SANDBOX_CAMPAIGN_COLOR | `string` |  | string | `"#7a01e5"` | Label color for campaign. |
| HATCHING_TRIAGE_SANDBOX_TAG_COLOR | `string` |  | string | `"#54483b"` | Label color for all other labels. |
| HATCHING_TRIAGE_SANDBOX_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP marking for observable submission. |
