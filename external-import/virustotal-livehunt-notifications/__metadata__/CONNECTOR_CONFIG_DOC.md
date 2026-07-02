# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | VirusTotal Premium API key. |
| CONNECTOR_NAME | `string` |  | string |  | `"VirusTotal Livehunt Notifications"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["StixFile", "Indicator", "Incident", "Domain-Name", "Url", "IPv4-Addr", "IPv6-Addr"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT5M"` | The period of time to await between two runs of the connector. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` |  | `"clear"` | Default TLP level of the imported entities. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_ALERT | `boolean` |  | boolean |  | `true` | Create incident/alert for each notification. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_ALERT_PREFIX | `string` |  | string |  | `"VT "` | Prefix that is added in alerts titles. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_DELETE_NOTIFICATION | `boolean` |  | boolean |  | `false` | Delete notification from VT after processing. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_FILTER_WITH_TAG | `string` |  | string |  | `null` | Only process notifications with this tag. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_FILE | `boolean` |  | boolean |  | `true` | Create file observable for matched files. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_EXTENSIONS | `array` |  | string |  | `[]` | Comma-separated file extensions to filter (e.g., `exe,dll`). |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MAX_AGE_DAYS | `integer` |  | integer |  | `3` | Only process files submitted within this many days. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MIN_FILE_SIZE | `integer` |  | integer |  | `1000` | Minimum file size in bytes to download. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MAX_FILE_SIZE | `integer` |  | integer |  | `52428800` | Maximum file size in bytes to download(default: 50MB). |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MIN_POSITIVES | `integer` |  | integer |  | `1` | Minimum number of vendors marking file to download as 'malicious'. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_UPLOAD_ARTIFACT | `boolean` |  | boolean |  | `false` | Upload file to OpenCTI as artifact. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_YARA_RULE | `boolean` |  | boolean |  | `true` | Create YARA indicator for the matching rule. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_AV_LIST | `array` |  | string |  | `[]` | Comma-separated list of AVs to add in description, (e.g., `Kaspersky,Symantec`). |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_LIVEHUNT_TAG_PREFIX | `string` |  | string |  | `""` | Prefix used to state that the tag is imported from Livehunt |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_YARA_LABEL_PREFIX | `string` |  | string |  | `"vt:yara:"` | Prefix that is added in yara labels. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_LIVEHUNT_LABEL_PREFIX | `string` |  | string |  | `"vt:lh:"` | Prefix that is added in livehunt labels. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_ENABLE_LABEL_ENRICHMENT | `boolean` |  | boolean |  | `true` | Add livehunt name and matched yara rules label to the alert |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_GET_MALWARE_CONFIG | `boolean` |  | boolean |  | `false` | Extract C2 infrastructure (domains, IPs, URLs) from VirusTotal's malware configuration analysis and add the resulting observables to the bundle. Only effective when ``create_file`` is true. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_FILE_INDICATORS | `boolean` |  | boolean |  | `false` | Create a File indicator (SHA-256 pattern) for each matched file. Only effective when ``create_file`` is true — the File indicator is emitted alongside the File observable in ``LivehuntBuilder.create_file``, so leaving ``create_file`` off means this flag has no effect. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_DOMAIN_NAME_INDICATORS | `boolean` |  | boolean |  | `false` | Create Domain-Name indicators for domains extracted from the malware configuration. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_IP_INDICATORS | `boolean` |  | boolean |  | `false` | Create IPv4/IPv6 indicators for IP addresses extracted from the malware configuration. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_URL_INDICATORS | `boolean` |  | boolean |  | `false` | Create URL indicators for URLs extracted from the malware configuration. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_LIMIT | `integer` |  | `1 <= x ` |  | `null` | Maximum number of notifications to process per run. Useful when the VirusTotal API quota is small. Leave unset to process every available notification. |
| VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
