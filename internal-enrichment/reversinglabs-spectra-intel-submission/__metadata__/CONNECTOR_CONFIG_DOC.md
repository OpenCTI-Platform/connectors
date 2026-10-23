# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_USERNAME | `string` | ✅ | string |  |  | ReversingLabs Spectra Intelligence username. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | ReversingLabs Spectra Intelligence password. |
| CONNECTOR_NAME | `string` |  | string |  | `"ReversingLabs Spectra Intelligence Submission"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Artifact", "Url", "StixFile", "File"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_URL | `string` |  | string |  | `"data.reversinglabs.com"` | ReversingLabs Spectra Intelligence API base URL. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_SANDBOX_OS | `string` |  | `windows7` `windows10` `windows11` `macos11` `linux` |  | `"windows10"` | The platform to execute the sample on. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_SANDBOX_INTERNET_SIM | `boolean` |  | boolean |  | `false` | Enable internet simulation during sandbox analysis. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_CREATE_INDICATORS | `boolean` |  | boolean |  | `true` | Create STIX indicators from analysis results. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_POLL_INTERVAL | `integer` |  | `250 <= x ` |  | `250` | Polling interval in seconds to check analysis results. |
| REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_MAX_TLP | `string` |  | string | ⛔️ | `null` | Use CONNECTOR_MAX_TLP instead. |
