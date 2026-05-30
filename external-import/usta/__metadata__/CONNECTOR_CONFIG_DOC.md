# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| USTA_API_KEY | `string` | ✅ | string |  | USTA API bearer token for authentication. |
| CONNECTOR_NAME | `string` |  | string | `"USTA"` | The name of the connector. |
| CONNECTOR_SCOPE | `string` |  | string | `"indicator,observable,malware,identity,incident,user-account,report,threat-actor"` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT30M"` | The period of time to await between two runs. |
| USTA_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://usta.prodaft.com"` | USTA API base URL. |
| USTA_IMPORT_START_DATE | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"P90D"` | ISO 8601 duration string specifying how far back to import data (e.g., P90D for 90 days, P30D for 30 days). Only used on the very first run when no state exists. |
| USTA_PAGE_SIZE | `integer` |  | `1 <= x <= 500` | `100` | Number of records to fetch per API page. |
| USTA_IMPORT_MALICIOUS_URLS | `boolean` |  | boolean | `true` | Enable import of malicious URL indicators. |
| USTA_IMPORT_PHISHING_SITES | `boolean` |  | boolean | `true` | Enable import of phishing site indicators. |
| USTA_IMPORT_MALWARE_HASHES | `boolean` |  | boolean | `true` | Enable import of malware hash indicators. |
| USTA_IMPORT_COMPROMISED_CREDENTIALS | `boolean` |  | boolean | `true` | Enable import of compromised credentials tickets (Account Takeover Prevention). |
| USTA_IMPORT_CREDIT_CARDS | `boolean` |  | boolean | `true` | Enable import of compromised credit card tickets (Fraud Intelligence). |
| USTA_IMPORT_DEEP_SIGHT_TICKETS | `boolean` |  | boolean | `true` | Enable import of Deep Sight intelligence tickets (threat reports, leaks, APT activity). |
| USTA_STORE_CREDENTIAL_PASSWORD | `boolean` |  | boolean | `false` | When enabled, the raw password from Account Takeover Prevention records is stored in the STIX User-Account credential field. Disabled by default for security reasons. |
| USTA_TLP_LEVEL | `string` |  | `clear` `white` `green` `amber` `red` | `"red"` | TLP marking level to apply to imported data. |
| USTA_CONFIDENCE_LEVEL | `integer` |  | `0 <= x <= 100` | `99` | Confidence level for created STIX objects (0-100). |
