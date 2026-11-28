# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |  |
| DARKMOON_EXPORT_PATH | `string` | ✅ | Format: [`path`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Absolute path, inside the connector container, to the Darkmoon OSS data directory. This is the host directory the Darkmoon stack mounts at `/root/.local/share/opencode` (named `darkmoon-settings` in the reference docker-compose). It must contain the `campaigns/`, `vulnerabilities/` subdirectories and, optionally, a `targets.json` file. | ```/opt/darkmoon-data``` |
| CONNECTOR_NAME | `string` |  | string | `"Darkmoon"` | The name of the connector. |  |
| CONNECTOR_SCOPE | `array` |  | string | `["Vulnerability", "Note", "Report", "Attack-Pattern"]` | The scope of the connector, i.e. the type of entities it imports. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). |  |
| DARKMOON_IMPORT_SINCE | `string` |  | Format: [`date-time`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The start date (ISO 8601) for importing campaigns. Can be absolute (e.g. '2026-01-01T00:00:00Z') or relative (e.g. 'P30D' meaning '30 days ago'). Used as the initial checkpoint on the connector's first run; subsequent runs resume from the connector state. |  |
| DARKMOON_IMPORT_FINDINGS | `boolean` |  | boolean | `true` | Enable/disable the import of findings (vulnerabilities + evidence notes). |  |
| DARKMOON_IMPORT_ATTACK_PATTERNS | `boolean` |  | boolean | `true` | Create an Attack Pattern (and a relationship to the vulnerability) for each finding that carries a MITRE ATT&CK technique id. |  |
| DARKMOON_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"red"` | Default TLP (Traffic Light Protocol) marking applied to every object this connector creates. Darkmoon findings describe your own infrastructure, so a restrictive marking is recommended. |  |
