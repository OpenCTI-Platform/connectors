# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| ABUSEIPDB_TAXII_USERNAME | `string` | ✅ | string |  | AbuseIPDB account email, used as the HTTP Basic authentication username for the TAXII API. |
| ABUSEIPDB_TAXII_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | An AbuseIPDB API key (not the account password), used as the HTTP Basic authentication password for the TAXII API. |
| CONNECTOR_NAME | `string` |  | string | `"AbuseIPDB TAXII"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["abuseipdb-taxii"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT1H"` | Time to wait between two runs of the connector, as an ISO 8601 duration (e.g. `PT1H` for one hour). |
| ABUSEIPDB_TAXII_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://taxii.abuseipdb.com/taxii2/abuseipdb-taxii2/"` | Base URL of the AbuseIPDB TAXII 2.1 API root. |
| ABUSEIPDB_TAXII_COLLECTION_ID | `string` |  | string | `null` | Collection ID of the AbuseIPDB TAXII feed to import, as shown on the account's My TAXII Feeds page. Only needed when the account has more than one feed. |
| ABUSEIPDB_TAXII_IMPORT_SINCE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) | `"P30D"` | Start of the import window on the connector's first run, as an ISO 8601 duration relative to now (e.g. 'P30D' for 30 days ago) or an absolute ISO 8601 datetime. Later runs resume from the connector state. Feeds whose position is kept by AbuseIPDB ignore it. |
| ABUSEIPDB_TAXII_PAGE_SIZE | `integer` |  | `10 <= x <= 1000` | `1000` | Number of STIX objects requested per TAXII page. This does not limit the total number of objects retrieved per run. |
| ABUSEIPDB_TAXII_VERIFY_SSL | `boolean` |  | boolean | `true` | Whether to verify the TAXII server's TLS certificate. |
| ABUSEIPDB_TAXII_REQUEST_TIMEOUT_SECONDS | `number` |  | `0 < x ` | `60.0` | Timeout, in seconds, applied to each TAXII HTTP request. |
