# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| WIZ_CLOUD_API_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Tenant GraphQL endpoint, e.g. https://api.us17.app.wiz.io/graphql |
| WIZ_CLOUD_CLIENT_ID | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Wiz service account client id |
| WIZ_CLOUD_CLIENT_SECRET | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Wiz service account client secret |
| CONNECTOR_NAME | `string` |  | string | `"Wiz Cloud"` |  |
| CONNECTOR_SCOPE | `array` |  | string | `["wiz-cloud"]` |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT6H"` |  |
| WIZ_CLOUD_AUTH_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://auth.app.wiz.io/oauth/token"` | OAuth2 token endpoint (different host than api_url) |
| WIZ_CLOUD_ISSUE_SEVERITY | `array` |  | string | `["CRITICAL", "HIGH"]` | Issue severities to import (comma-separated). E.g. 'CRITICAL,HIGH,MEDIUM,LOW,INFORMATIONAL'. |
| WIZ_CLOUD_ISSUE_STATUS | `array` |  | string | `["OPEN", "IN_PROGRESS"]` | Issue statuses to import (comma-separated). E.g. 'OPEN,IN_PROGRESS,RESOLVED,REJECTED'. |
| WIZ_CLOUD_IMPORT_TTPS | `boolean` |  | boolean | `true` | Whether to import the MITRE ATT&CK techniques mapped to the source rules of the imported issues. They are returned by the issues query itself, so importing them costs no extra API call. |
| WIZ_CLOUD_IMPORT_VULNERABILITIES | `boolean` |  | boolean | `false` | Whether to import vulnerability findings for the cloud assets referenced by the imported issues. |
| WIZ_CLOUD_VULNERABILITY_SEVERITY | `array` |  | string | `["CRITICAL", "HIGH"]` | Vulnerability severities to import (comma-separated). E.g. 'CRITICAL,HIGH,MEDIUM,LOW,NONE'. |
| WIZ_CLOUD_VULNERABILITY_STATUS | `array` |  | string | `["OPEN", "IN_PROGRESS"]` | Vulnerability statuses to import (comma-separated). E.g. 'OPEN,IN_PROGRESS,RESOLVED,REJECTED'. |
| WIZ_CLOUD_VULNERABILITY_HAS_EXPLOIT | `boolean` |  | boolean | `false` | Import only vulnerabilities with a known exploit. Severity alone barely reduces the volume, so this is the effective filter when an asset carries hundreds of findings. |
| WIZ_CLOUD_SINCE | `string` |  | [`^(?:(?!0000\|0001\|9999)(?:\d{4}-(?:0[13578]\|1[02])-(?:0[1-9]\|[12]\d\|3[01])\|\d{4}-(?:0[469]\|11)-(?:0[1-9]\|[12]\d\|30)\|\d{4}-02-(?:0[1-9]\|1\d\|2[0-8])\|(?:\d\d(?:0[48]\|[2468][048]\|[13579][26])\|(?:[02468][048]\|[13579][26])00)-02-29)(?:[T ](?:[01]\d\|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z\|[+-](?:[01]\d\|2[0-3])(?::?[0-5]\d)?)?)?\|P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?)$`](https://regex101.com/?regex=%5E%28%3F%3A%28%3F%210000%7C0001%7C9999%29%28%3F%3A%5Cd%7B4%7D-%28%3F%3A0%5B13578%5D%7C1%5B02%5D%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C3%5B01%5D%29%7C%5Cd%7B4%7D-%28%3F%3A0%5B469%5D%7C11%29-%28%3F%3A0%5B1-9%5D%7C%5B12%5D%5Cd%7C30%29%7C%5Cd%7B4%7D-02-%28%3F%3A0%5B1-9%5D%7C1%5Cd%7C2%5B0-8%5D%29%7C%28%3F%3A%5Cd%5Cd%28%3F%3A0%5B48%5D%7C%5B2468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%29%7C%28%3F%3A%5B02468%5D%5B048%5D%7C%5B13579%5D%5B26%5D%2900%29-02-29%29%28%3F%3A%5BT+%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%3A%5B0-5%5D%5Cd%28%3F%3A%3A%5B0-5%5D%5Cd%28%3F%3A%5C.%5Cd%2B%29%3F%29%3F%28%3F%3AZ%7C%5B%2B-%5D%28%3F%3A%5B01%5D%5Cd%7C2%5B0-3%5D%29%28%3F%3A%3A%3F%5B0-5%5D%5Cd%29%3F%29%3F%29%3F%7CP%28%3F%21%24%29%28%3F%3A%5Cd%7B1%2C3%7DY%29%3F%28%3F%3A%5Cd%7B1%2C3%7DM%29%3F%28%3F%3A%5Cd%7B1%2C3%7DW%29%3F%28%3F%3A%5Cd%7B1%2C4%7DD%29%3F%28%3F%3AT%28%3F%3D%5Cd%29%28%3F%3A%5Cd%7B1%2C4%7DH%29%3F%28%3F%3A%5Cd%7B1%2C4%7DM%29%3F%28%3F%3A%5Cd%7B1%2C4%7D%28%3F%3A%5C.%5Cd%2B%29%3FS%29%3F%29%3F%29%24) |  | Relative import start on first run (ISO 8601 duration) |
| WIZ_CLOUD_PAGE_SIZE | `integer` |  | `1 <= x <= 100` | `50` |  |
| WIZ_CLOUD_MARKING | `string` |  | `clear` `white` `green` `amber` `amber+strict` `red` | `"amber+strict"` | TLP Level Enum.<br /><br />See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/identifier.js#L76 |
