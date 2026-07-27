# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| SOCPRIME_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | API key used to authenticate against the SOC Prime TDM API. |
| CONNECTOR_NAME | `string` |  | string |  | `"SocPrime"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["socprime"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| SOCPRIME_CONTENT_LIST_NAME | `array` |  | string |  | `[]` | List of SOC Prime content list names to import rules from. At least one of `SOCPRIME_CONTENT_LIST_NAME` and `SOCPRIME_JOB_IDS` parameters has to be provided. If `SOCPRIME_CONTENT_LIST_NAME` is provided, then the parameter `SOCPRIME_INDICATOR_SIEM_TYPE` has to be provided too. |
| SOCPRIME_JOB_IDS | `array` |  | string |  | `[]` | List of SOC Prime job ids to import rules from. At least one of `SOCPRIME_CONTENT_LIST_NAME` and `SOCPRIME_JOB_IDS` parameters has to be provided. |
| SOCPRIME_SIEM_TYPE | `array` |  | string |  | `[]` | List of SIEM types to request rules for (used with job ids). |
| SOCPRIME_INDICATOR_SIEM_TYPE | `string` |  | `sigma` `ala-rule` `ala` `elasticsearch` `es-eql` `xpack-watcher` `elasticsearch-rule` `es-rule-eql` `kibana` `elastalert` `qradar` `humio` `humio-alert` `splunk` `splunk_alert` `sumologic` `sumologic-cse` `sumologic-cse-rule` `arcsight-esm` `arcsight-keyword` `logpoint` `grep` `powershell` `graylog` `kafka` `rsa_netwitness` `carbonblack` `carbonblack-edr` `open-ioc` `fireeye-helix` `chronicle` `securonix` `s1-events` `s1-process` `mdatp` `qualys` `sysmon` `crowdstrike` `limacharlie` `devo` `snowflake` `athena` `opendistro-query` `opendistro-rule` `fortisiem` `axon-ads-query` `axon-ads-rule` |  | `"sigma"` | SIEM type used to render rules imported from content lists. Only applicable to `SOCPRIME_CONTENT_LIST_NAME` parameter and not to `SOCPRIME_JOB_IDS` |
| SOCPRIME_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"amber+strict"` | TLP marking applied to imported entities. |
| SOCPRIME_INTERVAL_SEC | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
