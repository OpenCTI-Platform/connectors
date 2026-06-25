# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| JOE_SANDBOX_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API key for Joe Sandbox |
| CONNECTOR_NAME | `string` |  | string | `"Joe Sandbox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["Artifact", "Url"]` | The scope of the connector, i.e., the types of entities the connector can enrich. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| JOE_SANDBOX_REPORT_TYPES | `string` |  | string | `"executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection"` | Download/upload as external ref files for these report types. json/xml are only allowed to be used with Joe Sandbox Cloud Pro |
| JOE_SANDBOX_API_URL | `string` |  | string | `"https://jbxcloud.joesecurity.org/api"` | Cloud Pro: https://jbxcloud.joesecurity.org/api, Cloud Basic: https://joesandbox.com/api |
| JOE_SANDBOX_ANALYSIS_URL | `string` |  | string | `"https://jbxcloud.joesecurity.org/analysis"` | Cloud Pro: https://jbxcloud.joesecurity.org/analysis, Cloud Basic: https://joesandbox.com/analysis |
| JOE_SANDBOX_ACCEPT_TAC | `boolean` |  | boolean | `true` | If true you accept Terms and Conditions at https://jbxcloud.joesecurity.org/tandc |
| JOE_SANDBOX_API_TIMEOUT | `integer` |  | integer | `30` | Time in seconds to timeout after calling Joe Sandbox API |
| JOE_SANDBOX_VERIFY_SSL | `boolean` |  | boolean | `true` | Verify SSL for API calls |
| JOE_SANDBOX_API_RETRIES | `integer` |  | integer | `5` | How many times to retry API calls before giving up |
| JOE_SANDBOX_PROXIES | `string` |  | string | `null` | A JSON encoded map of proxies to use for API calls. See https://requests.readthedocs.io/en/latest/user/advanced/?highlight=proxy#proxies |
| JOE_SANDBOX_USER_AGENT | `string` |  | string | `"OpenCTI"` | The user agent. Use this when you write an integration with Joe Sandbox so that it is possible to track how often an integration is being used. |
| JOE_SANDBOX_SYSTEMS | `string` |  | string | `"w10x64_office"` | Analysis systems to use (comma separated if multiple) |
| JOE_SANDBOX_ANALYSIS_TIME | `integer` |  | integer | `300` | Timeout for the analysis |
| JOE_SANDBOX_INTERNET_ACCESS | `boolean` |  | boolean | `true` | Enable full internet access in the analysis (must be false if internet simulation is true) |
| JOE_SANDBOX_INTERNET_SIMULATION | `boolean` |  | boolean | `false` | Enable internet simulation (must be false if internet access is true) |
| JOE_SANDBOX_HYBRID_CODE_ANALYSIS | `boolean` |  | boolean | `true` | Enable Hybrid Code Analysis (HCA). |
| JOE_SANDBOX_HYBRID_DECOMPILATION | `boolean` |  | boolean | `true` | Enable Hybrid Decompilation (DEC). |
| JOE_SANDBOX_REPORT_CACHE | `boolean` |  | boolean | `false` | Enable the report cache. Check the cache for existing reports before running a full analysis. |
| JOE_SANDBOX_APK_INSTRUMENTATION | `boolean` |  | boolean | `true` | Perform APK DEX code instrumentation. |
| JOE_SANDBOX_AMSI_UNPACKING | `boolean` |  | boolean | `true` | Perform generic unpacking using the Microsoft Antimalware Scan Interface (AMSI). |
| JOE_SANDBOX_SSL_INSPECTION | `boolean` |  | boolean | `true` | Enable HTTPS inspection. |
| JOE_SANDBOX_VBA_INSTRUMENTATION | `boolean` |  | boolean | `false` | Enable VBA instrumentation (two analyses are performed) |
| JOE_SANDBOX_JS_INSTRUMENTATION | `boolean` |  | boolean | `false` | Enable Javascript instrumentation (two analyses are performed) |
| JOE_SANDBOX_JAVA_JAR_TRACING | `boolean` |  | boolean | `false` | Enable JAVA JAR tracing (two analyses are performed) |
| JOE_SANDBOX_DOTNET_TRACING | `boolean` |  | boolean | `false` | Enable .NET tracing (two analyses are performed) |
| JOE_SANDBOX_START_AS_NORMAL_USER | `boolean` |  | boolean | `false` | Starts the Sample with normal user privileges |
| JOE_SANDBOX_SYSTEM_DATE | `string` |  | string | `null` | Change the analyzer's system date (helpful for date-aware samples), format is: YYYY-MM-DD |
| JOE_SANDBOX_LANGUAGE_AND_LOCALE | `string` |  | string | `null` | Changes the language and locale of the analysis machine |
| JOE_SANDBOX_LOCALIZED_INTERNET_COUNTRY | `string` |  | string | `null` | Select the country to use for routing internet access through. |
| JOE_SANDBOX_EMAIL_NOTIFICATION | `boolean` |  | boolean | `null` | Enable email notification |
| JOE_SANDBOX_ARCHIVE_NO_UNPACK | `boolean` |  | boolean | `false` | Do not unpack archives (zip, 7z etc) containing multiple files. |
| JOE_SANDBOX_HYPERVISOR_BASED_INSPECTION | `boolean` |  | boolean | `false` | Enable Hypervisor based Inspection |
| JOE_SANDBOX_FAST_MODE | `boolean` |  | boolean | `false` | Fast Mode focuses on fast analysis and detection versus deep forensic analysis. |
| JOE_SANDBOX_SECONDARY_RESULTS | `boolean` |  | boolean | `true` | Enables secondary results such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. Analysis will run faster with disabled secondary results |
| JOE_SANDBOX_COOKBOOK_FILE_PATH | `string` |  | string | `null` | Path to a cookbook to run for the analysis |
| JOE_SANDBOX_DOCUMENT_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"**********"` | Password for decrypting documents like MS Office and PDFs |
| JOE_SANDBOX_ARCHIVE_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"**********"` | This password will be used to decrypt archives (zip, 7z, rar etc.). |
| JOE_SANDBOX_COMMAND_LINE_ARGUMENT | `string` |  | string | `null` | Will start the sample with the given command-line argument. Currently only available on Windows analyzers. |
| JOE_SANDBOX_ENCRYPT_WITH_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Encryption password for analyses, AES-256 is used to encrypt files and the password is deleted on the backend after encrypting files |
| JOE_SANDBOX_BROWSER | `boolean` |  | boolean | `false` | Use a browser for analysis of URLs, false == download/execute |
| JOE_SANDBOX_URL_REPUTATION | `boolean` |  | boolean | `false` | Lookup the reputation of URLs and domains to improve the analysis. This option will send URLs and domains to third party services and WHOIS servers! |
| JOE_SANDBOX_EXPORT_TO_JBXVIEW | `boolean` |  | boolean | `false` | Export the report(s) from this analysis to Joe Sandbox View. |
| JOE_SANDBOX_DELETE_AFTER_DAYS | `integer` |  | integer | `30` | Delete the analysis after X days. If not set, the default value is used |
| JOE_SANDBOX_PRIORITY | `integer` |  | integer | `null` | ON PREMISE EXCLUSIVE PARAMETER, set the priority of the submission between 1 and 10, high value means higher priority |
| JOE_SANDBOX_DEFAULT_TLP | `string` |  | string | `"TLP:CLEAR"` | The default TLP for newly created stix objects |
| JOE_SANDBOX_YARA_COLOR | `string` |  | string | `"#0059f7"` | The color for yara labels applied to the observable |
| JOE_SANDBOX_DEFAULT_COLOR | `string` |  | string | `"#54483b"` | The color for default labels |
