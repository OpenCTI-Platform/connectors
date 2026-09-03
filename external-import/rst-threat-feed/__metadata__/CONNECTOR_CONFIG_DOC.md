# Connector Configurations

Below is a list of the environment variables supported by the RST
Threat Feed connector. Required values must be supplied before starting the
connector.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` (URL) | Yes | URL |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | Yes |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | `RST Threat Feed`, `RST Threat Feed - Domain` | `"RST Threat Feed"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` | Yes |  |  | The scope of the connector, e.g. 'indicator, vulnerability'. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug`, `info`, `warn`, `warning`, `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `string` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` (ISO-8601 duration) |  | `PT24H`, `PT1H`, `PT12H` | `"P1D"` | The period of time to await between two runs of the connector. Prefer ISO-8601 (e.g. PT24H). Legacy RST_THREAT_FEED_INTERVAL (seconds) is still accepted and mapped here. |
| CONNECTOR_QUEUE_THRESHOLD | `number` |  | `500.0` | `500.0` | Server capacity: max RabbitMQ queue size (in MB) before the connector pauses ingestion. Surfaced in the OpenCTI UI. |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | `true`, `false` | `true` | Whether to update existing STIX objects in OpenCTI. |
| CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT | `boolean` |  | `true`, `false` | `false` | Create a dedicated Connectors-group service account for this connector on first start and run subsequent API calls as that user. |
| CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT_CONFIDENCE_LEVEL | `integer` |  | `50`, `80` | `50` | Max confidence level for the auto-created connector service account. |
| RST_THREAT_FEED_BASEURL | `string` (URL) |  | URL | `"https://api.rstcloud.net/v1"` | RST Cloud API base URL. |
| RST_THREAT_FEED_APIKEY | `string` | Yes | `ChangeMe` |  | RST Cloud Threat Feed API key. |
| RST_THREAT_FEED_CONTIMEOUT | `integer` |  | `30` | `30` | HTTP connect timeout in seconds. |
| RST_THREAT_FEED_READTIMEOUT | `integer` |  | `120`, `600` | `120` | HTTP read timeout in seconds for feed downloads. |
| RST_THREAT_FEED_RETRY | `integer` |  | `2` | `2` | Per-request HTTP retry count for feed downloads. |
| RST_THREAT_FEED_SSL_VERIFY | `boolean` |  | `true`, `false` | `true` | Verify TLS certificates for API requests. |
| RST_THREAT_FEED_PROXY | `string` |  | ``, `http://proxy.example.com:8080` | `""` | Optional explicit forward proxy URL for feed downloads. When empty (default), requests honor standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY environment variables. |
| RST_THREAT_FEED_LATEST | `string` |  | `day`, `1h`, `4h`, `12h` | `"day"` | Which feed snapshot window to download. |
| RST_THREAT_FEED_INTERVAL | `integer` |  | `86400`, `3600` | `null` | Deprecated. Run interval in seconds. Prefer CONNECTOR_DURATION_PERIOD. When set, overrides duration_period. |
| RST_THREAT_FEED_IP | `boolean` |  | `true`, `false` | `true` | Import the IP indicator feed. |
| RST_THREAT_FEED_DOMAIN | `boolean` |  | `true`, `false` | `true` | Import the Domain indicator feed. |
| RST_THREAT_FEED_URL | `boolean` |  | `true`, `false` | `true` | Import the URL indicator feed. |
| RST_THREAT_FEED_HASH | `boolean` |  | `true`, `false` | `true` | Import the Hash (file) indicator feed. |
| RST_THREAT_FEED_MIN_SCORE_IMPORT | `integer` |  | `20`, `40` | `20` | Import only indicators with total score at or above this value. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_IP | `integer` |  | `45` | `45` | Score threshold for x_opencti_detection on IPv4 indicators. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_DOMAIN | `integer` |  | `45` | `45` | Score threshold for x_opencti_detection on Domain indicators. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_URL | `integer` |  | `45` | `45` | Score threshold for x_opencti_detection on URL indicators. |
| RST_THREAT_FEED_MIN_SCORE_DETECTION_HASH | `integer` |  | `45` | `45` | Score threshold for x_opencti_detection on Hash indicators. |
| RST_THREAT_FEED_ONLY_NEW | `boolean` |  | `true`, `false` | `true` | Skip indicators whose last-seen is older than the collect window. |
| RST_THREAT_FEED_ONLY_ATTRIBUTED | `boolean` |  | `true`, `false` | `false` | Import only indicators attributed to known threats. |
| RST_THREAT_FEED_KEEP_NAMED_VULNS | `boolean` |  | `true`, `false` | `true` | Create named vulnerability objects (e.g. printnightmare). |
| RST_THREAT_FEED_CREATE_MITRE_TTPS | `boolean` |  | `true`, `false` | `false` | Create Attack-Pattern objects for MITRE TTP IDs and relate them to indicators. Can produce a large number of relationships. |
| RST_THREAT_FEED_CREATE_CUSTOM_TTPS | `boolean` |  | `true`, `false` | `true` | Create custom Attack-Pattern objects for named techniques not yet covered by MITRE ATT&CK. |
| RST_THREAT_FEED_MAX_RETRIES | `integer` |  | `3` | `3` | Maximum attempts when pushing bundles to OpenCTI. |
| RST_THREAT_FEED_RETRY_DELAY | `integer` |  | `10` | `10` | Initial retry delay in seconds for OpenCTI push failures. The connector sleeps at least 1 second between retries. |
| RST_THREAT_FEED_RETRY_BACKOFF_MULTIPLIER | `number` |  | `2.0` | `2.0` | Exponential backoff multiplier for OpenCTI push retries. |
| RST_THREAT_FEED_OPENCTI_BATCH_SIZE | `integer` |  | `100`, `200`, `500` | `200` | Max STIX objects per OpenCTI push. Large feeds (especially Domain) are flushed in chunks to bound memory and avoid oversized works. |
