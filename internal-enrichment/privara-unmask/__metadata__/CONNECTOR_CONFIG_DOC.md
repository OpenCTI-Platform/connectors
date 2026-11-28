# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| PRIVARA_UNMASK_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Unmask API key (pvu_...) with the `submit` and `read` scopes. Create it at https://app.tajapps.com/dashboard/unmask/api (sign up at https://tajapps.com/unmask/). |
| CONNECTOR_NAME | `string` |  | string | `"Privara Unmask"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact", "StixFile"]` | The OpenCTI entity types the connector enriches (files carrying an Android package). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| CONNECTOR_MAX_TLP | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber"` | The highest TLP of the entities the connector is allowed to enrich. Entities marked with a higher TLP are skipped and never sent to the external source. |
| PRIVARA_UNMASK_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://app.tajapps.com/api/unmask/v1"` | Unmask API base URL. |
| PRIVARA_UNMASK_MAX_WAIT | `integer` |  | `0 < x ` | `3600` | Longest time in seconds to wait for one analysis before giving up (the analysis keeps running; enriching the file again within 24 hours picks up the same job at no extra cost). |
| PRIVARA_UNMASK_POLL_INTERVAL | `integer` |  | `0 < x ` | `30` | First delay in seconds between two status checks when the API gives no Retry-After (it grows up to 120 s; never below 15 s). |
| PRIVARA_UNMASK_MAX_FILE_SIZE_MB | `integer` |  | `0 < x ` | `null` | Optional lower size cap in MB. By default the API's own limit is used (GET /balance, limits.max_file_mb). |
| PRIVARA_UNMASK_CREATE_OBSERVABLES | `boolean` |  | boolean | `true` | Also create an observable (URL, IP, domain) for each C2 indicator. |
| PRIVARA_UNMASK_NOTIFY_EMAIL | `boolean` |  | boolean | `null` | Send the Privara result e-mail for each analysis (unset: the account's own setting). |
