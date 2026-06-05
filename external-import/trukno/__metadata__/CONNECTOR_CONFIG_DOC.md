# Connector Configurations

Below is an exhaustive enumeration of the configurable parameters currently supported by the TruKno connector.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: `uri` |  | The OpenCTI platform URL. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The token used by the connector to authenticate to OpenCTI. |
| CONNECTOR_ID | `string` |  | string |  | A stable UUID for this connector instance. |
| CONNECTOR_NAME | `string` |  | string | `"TruKno"` | Name of the connector shown in OpenCTI. |
| CONNECTOR_SCOPE | `array` |  | string | `["report", "attack-pattern", "malware"]` | STIX object scope currently imported by the connector. |
| CONNECTOR_TYPE | `string` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` | Connector type for OpenCTI. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | Determines the verbosity of runtime logs. |
| TRUKNO_API_BASE_URL | `string` |  | Format: `uri` | `"https://api.trukno.com/v2"` | Base URL of the TruKno API. |
| TRUKNO_API_KEY | `string` | ✅ | string |  | API key used to authenticate to TruKno. |
| TRUKNO_INTERVAL_MINUTES | `integer` |  | `0 < x` | `60` | Polling interval in minutes between connector cycles. |
| TRUKNO_INITIAL_LOOKBACK_DAYS | `integer` |  | `0 < x` | `30` | Number of days to backfill on the first run before a checkpoint exists. |
| TRUKNO_CONNECTOR_CONFIG | `string` |  | string |  | Optional explicit path to a `config.yml` file used for manual or packaged runs. |
