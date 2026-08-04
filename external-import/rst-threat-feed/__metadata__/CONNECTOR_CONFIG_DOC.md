# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| RST_THREAT_FEED_APIKEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Your API Key for accessing RST Cloud. |
| CONNECTOR_NAME | `string` |  | string |  | `"RstThreatFeed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `[]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT1H"` | The period of time to await between two runs of the connector. |
| RST_THREAT_FEED_BASEURL | `string` |  | string |  | `"https://api.rstcloud.net/v1"` | RST Threat Feed Base URL. By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint. |
| RST_THREAT_FEED_SSL_VERIFY | `boolean` |  | boolean |  | `true` | If set to false, SSL verification is disabled (use with caution, sometimes needed when SSL inspection is enabled). |
| RST_THREAT_FEED_CONTIMEOUT | `integer` |  | integer |  | `30` | Connection timeout (seconds) to the RST Threat Feed API. |
| RST_THREAT_FEED_READTIMEOUT | `integer` |  | integer |  | `120` | Read timeout (seconds) for each feed download (API redirects to AWS S3). |
| RST_THREAT_FEED_RETRY | `integer` |  | integer |  | `2` | Number of attempts to download the feed. |
| RST_THREAT_FEED_INTERVAL | `integer` |  | integer |  | `86400` | Fetch interval in seconds (how often the connector will run for the feed download). |
| RST_THREAT_FEED_MAX_RETRIES | `integer` |  | integer |  | `3` | Maximum number of retry attempts for connection issues when sending the STIX bundle to OpenCTI. |
| RST_THREAT_FEED_RETRY_DELAY | `integer` |  | integer |  | `10` | Initial delay in seconds before retrying a failed connection to OpenCTI. |
| RST_THREAT_FEED_RETRY_BACKOFF_MULTIPLIER | `number` |  | number |  | `2.0` | Multiplier applied to the retry delay for exponential backoff between retries to send data to OpenCTI. |
| RST_THREAT_FEED_MIN_SCORE_IMPORT | `integer` |  | integer |  | `20` | Import only indicators with risk score more than this value. |
| RST_THREAT_FEED_LATEST | `string` |  | string |  | `"day"` | Defines how often the latest threat feed data is fetched. Options: 1h, 4h, 12h, day. |
| RST_THREAT_FEED_IP | `boolean` |  | boolean |  | `true` | If true, the connector retrieves threat intelligence data for IP addresses. |
| RST_THREAT_FEED_DOMAIN | `boolean` |  | boolean |  | `true` | If true, the connector retrieves threat intelligence data for domains. |
| RST_THREAT_FEED_URL | `boolean` |  | boolean |  | `true` | If true, the connector retrieves threat intelligence data for URLs. |
| RST_THREAT_FEED_HASH | `boolean` |  | boolean |  | `true` | If true, the connector retrieves threat intelligence data for file hashes (MD5, SHA1, SHA256). |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_IP | `integer` |  | integer |  | `45` | IP indicators with risk score more than this value are marked with x_opencti_detection=true. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_DOMAIN | `integer` |  | integer |  | `45` | Domain indicators with risk score more than this value are marked with x_opencti_detection=true. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_URL | `integer` |  | integer |  | `45` | URL indicators with risk score more than this value are marked with x_opencti_detection=true. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_HASH | `integer` |  | integer |  | `45` | Hash indicators with risk score more than this value are marked with x_opencti_detection=true. |
| RST_THREAT_FEED_ONLY_NEW | `boolean` |  | boolean |  | `true` | If true, import only indicators with recent "First Seen" (do not re-import older indicators based on "Last Seen"). |
| RST_THREAT_FEED_ONLY_ATTRIBUTED | `boolean` |  | boolean |  | `false` | If true, import only indicators that are attributed to known threats. |
| RST_THREAT_FEED_KEEP_NAMED_VULNS | `boolean` |  | boolean |  | `true` | If true, create named vulnerabilities as separate objects, otherwise prefer CVE numbers. |
| RST_THREAT_FEED_CREATE_CUSTOM_TTPS | `boolean` |  | boolean |  | `true` | If true, create custom attack-pattern objects for named techniques/attacks not present in MITRE ATT&CK. |
| RST_THREAT_FEED_CREATE_MITRE_TTPS | `boolean` |  | boolean |  | `false` | If true, create relationships: Indicator -> indicates -> Attack-Pattern (MITRE TTP). Will create many relationships, use with caution. |
| RST_THREAT_FEED_CREATE_MITRE_TTP | `boolean` |  | boolean | ⛔️ | `null` | Use RST_THREAT_FEED_CREATE_MITRE_TTPS instead. |
