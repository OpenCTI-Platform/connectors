# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string | `"YARA"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| YARA_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"clear"` | Default TLP marking to apply to created relationships when neither the artifact nor the indicator have markings. |
| YARA_PROPAGATE_MALWARE_RELATIONSHIP | `boolean` |  | boolean | `false` | When ``true``, for every YARA Indicator that matches the enriched Artifact, the connector follows the indicator's ``indicates`` relationships to Malware entities and emits an additional ``related-to`` STIX relationship from the Artifact to each of those Malware entities. Defaults to ``false`` to preserve the connector's previous behaviour. |
| YARA_PROPAGATE_LABELS | `boolean` |  | boolean | `false` | When ``true``, every OpenCTI label carried by a YARA Indicator that matches the enriched Artifact is added to the Artifact (via the ``stix_cyber_observable.add_label`` mutation). Defaults to ``false`` to preserve the connector's previous behaviour. |
