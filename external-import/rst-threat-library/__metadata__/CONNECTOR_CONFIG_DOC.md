# Connector Configurations

Below is an exhaustive list of the environment variables supported by the RST
Threat Library connector. Required values must be supplied before starting the
connector.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | Yes | URL | | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | Yes | string | | The API token used to connect to OpenCTI. |
| CONNECTOR_ID | `string` | Yes | UUID v4 | | A unique identifier for this connector instance. |
| CONNECTOR_TYPE | `const` | Yes | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` | The OpenCTI connector type. |
| CONNECTOR_NAME | `string` | Yes | string | `"RST Threat Library"` | The connector name displayed in OpenCTI. |
| CONNECTOR_SCOPE | `string` | Yes | string | `"intrusion-set,malware,tool,campaign"` | Comma-separated STIX domain types emitted by the connector. |
| CONNECTOR_LOG_LEVEL | `string` | | `debug`, `info`, `warn`, `warning`, `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_DURATION_PERIOD | `string` | | ISO-8601 duration | `"PT1H"` | The period between connector runs. |
| CONNECTOR_QUEUE_THRESHOLD | `number` | | Number greater than 0 | `500` | Maximum RabbitMQ queue size in MB before ingestion pauses. |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` | | `true`, `false` | `true` | Whether existing STIX objects may be updated. |
| CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT | `boolean` | | `true`, `false` | `false` | Whether to create a dedicated Connectors-group service account on first start. |
| CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT_CONFIDENCE_LEVEL | `integer` | | `0` to `100` | `50` | Maximum confidence level assigned to the auto-created service account. |
| RST_THREAT_LIBRARY_BASEURL | `string` | Yes | URL | `"https://api.rstcloud.net/v1"` | The RST Cloud Threat Library API base URL. |
| RST_THREAT_LIBRARY_APIKEY | `string` | Yes | string | | The RST Cloud Threat Library API key. |
| RST_THREAT_LIBRARY_AUTH_HEADER | `string` | | string | `"x-api-key"` | The HTTP header used to send the API key. |
| RST_THREAT_LIBRARY_PROXY | `string` | | URL or empty string | `""` | Optional forward HTTP proxy URL. An empty value uses direct egress. |
| RST_THREAT_LIBRARY_SSL_VERIFY | `boolean` | | `true`, `false` | `true` | Whether TLS certificates are verified for API requests. |
| RST_THREAT_LIBRARY_CONTIMEOUT | `integer` | | Positive integer | `30` | HTTP connection timeout in seconds. |
| RST_THREAT_LIBRARY_READTIMEOUT | `integer` | | Positive integer | `120` | HTTP read timeout in seconds. |
| RST_THREAT_LIBRARY_RETRY | `integer` | | Non-negative integer | `2` | Number of retries for each RST API request. |
| RST_THREAT_LIBRARY_MAX_RETRIES | `integer` | | Non-negative integer | `3` | Maximum retries when sending data to OpenCTI. |
| RST_THREAT_LIBRARY_RETRY_DELAY | `integer` | | Non-negative integer | `10` | Initial delay in seconds before retrying an OpenCTI push. |
| RST_THREAT_LIBRARY_RETRY_BACKOFF_MULTIPLIER | `number` | | Positive number | `2.0` | Exponential backoff multiplier for OpenCTI push retries. |
| RST_THREAT_LIBRARY_OPENCTI_PUSH_MODE | `string` | | `bundle`, `api` | `"bundle"` | The OpenCTI write path: worker bundle or GraphQL API import. |
| RST_THREAT_LIBRARY_OBJECT_TYPES | `string` | | Comma-separated string | `"intrusion-sets,malware,tools,campaigns"` | Threat-object API paths to poll. |
| RST_THREAT_LIBRARY_ORDER_BY | `string` | | string | `"modified"` | Field used to order API results for incremental synchronization. |
| RST_THREAT_LIBRARY_ORDER_MODE | `string` | | `asc`, `desc` | `"desc"` | Direction used to order API results. |
| RST_THREAT_LIBRARY_PAGE_SIZE | `integer` | | Positive integer | `100` | Maximum number of threat objects requested per page. |
| RST_THREAT_LIBRARY_MERGE_SPLIT | `boolean` | | `true`, `false` | `false` | Whether intrusion-set alias merge/split reconciliation is enabled. |
| RST_THREAT_LIBRARY_RESPECT_USER_EDITS | `boolean` | | `true`, `false` | `false` | Whether higher-confidence OpenCTI edits are preserved. |
| RST_THREAT_LIBRARY_INTRUSION_SET_DEFAULT_CONFIDENCE | `integer` | | `0` to `100` | | Optional confidence value that replaces upstream confidence on imported intrusion sets. |
| RST_THREAT_LIBRARY_SYNC_LABELS | `string` | | Comma-separated string | `"RST Threat Library"` | Labels applied during import and used to scope merge/split reconciliation. |
| RST_THREAT_LIBRARY_RECONCILE_EXCLUDE_LABELS | `string` | | Comma-separated string | `""` | Labels that exclude entities from merge/split fusion. |
| RST_THREAT_LIBRARY_RECONCILE_ALLOW_CREATED_BY | `string` | | Comma-separated identity IDs | `""` | When set, only entities created by these identities may be fused. |
| RST_THREAT_LIBRARY_IMPORT_FROM_DATE | `string` | | Date in `YYYY-MM-DD` format or empty string | `""` | Initial backfill cutoff. An empty value imports the full available history. |
