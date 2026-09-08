# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |
| TI_API_USERNAME | `string` | ✅ | string |  | Username used to authenticate against the Group-IB TI API. |
| TI_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | API token used to authenticate against the Group-IB TI API. |
| CONNECTOR_NAME | `string` |  | string | `"Group-IB Connector"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["stix2", "ipv4-addr", "ipv6-addr", "vulnerability", "domain", "url", "StixFile"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"info"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT4H"` | The period of time to await between two runs of the connector (ISO-8601 duration format). |
| CONNECTOR_UPDATE_EXISTING_DATA | `boolean` |  | boolean | `true` | Whether to update data already ingested into the platform. |
| TI_API_URL | `string` |  | string | `"https://tap.group-ib.com/api/v2/"` | Base URL of the Group-IB Threat Intelligence API. |
| TI_API_PROXY_IP | `string` |  | string | `null` | Optional proxy ip used to reach the Group-IB TI API. |
| TI_API_PROXY_PORT | `string` |  | string | `null` | Optional proxy port used to reach the Group-IB TI API. |
| TI_API_PROXY_PROTOCOL | `string` |  | string | `null` | Optional proxy protocol used to reach the Group-IB TI API. |
| TI_API_PROXY_USERNAME | `string` |  | string | `null` | Optional proxy username used to reach the Group-IB TI API. |
| TI_API_PROXY_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Optional proxy password used to reach the Group-IB TI API. |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_INDICATOR_THREAT_REPORTS | `boolean` |  | boolean | `false` | Extra setting 'ignore_non_indicator_threat_reports'. |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_INDICATOR_THREATS | `boolean` |  | boolean | `false` | Extra setting 'ignore_non_indicator_threats'. |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_MALWARE_DDOS | `boolean` |  | boolean | `true` | Extra setting 'ignore_non_malware_ddos'. |
| TI_API_EXTRA_SETTINGS_INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR | `boolean` |  | boolean | `false` | Extra setting 'intrusion_set_instead_of_threat_actor'. |
| TI_API_EXTRA_SETTINGS_SCHEDULE_TIME | `string` |  | string | `"00:00"` | Extra setting 'schedule_time'. |
| TI_API_EXTRA_SETTINGS_TIME_OUTPUT_FORMAT | `string` |  | string | `"%Y-%m-%d %H:%M:%S"` | Extra setting 'time_output_format'. |
| TI_API_EXTRA_SETTINGS_ENABLE_STATEMENT_MARKING | `boolean` |  | boolean | `false` | Extra setting 'enable_statement_marking'. |
| TI_API_COLLECTIONS_APT_THREAT_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'apt/threat' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_APT_THREAT_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'apt/threat' collection. |
| TI_API_COLLECTIONS_APT_THREAT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'apt/threat' collection. |
| TI_API_COLLECTIONS_APT_THREAT_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'apt/threat' collection. |
| TI_API_COLLECTIONS_APT_THREAT_USE_HUNTING_RULES | `boolean` |  | boolean | `false` | Apply Group-IB hunting rules when importing the 'apt/threat' collection. |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'apt/threat_actor' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'apt/threat_actor' collection. |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'apt/threat_actor' collection. |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'apt/threat_actor' collection. |
| TI_API_COLLECTIONS_ATTACKS_DDOS_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'attacks/ddos' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_ATTACKS_DDOS_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'attacks/ddos' collection. |
| TI_API_COLLECTIONS_ATTACKS_DDOS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'attacks/ddos' collection. |
| TI_API_COLLECTIONS_ATTACKS_DDOS_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'attacks/ddos' collection. |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'attacks/deface' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'attacks/deface' collection. |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'attacks/deface' collection. |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'attacks/deface' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'attacks/phishing_group' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'attacks/phishing_group' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'attacks/phishing_group' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'attacks/phishing_group' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'attacks/phishing_kit' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'attacks/phishing_kit' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'attacks/phishing_kit' collection. |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'attacks/phishing_kit' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/access' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/access' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/access' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'compromised/access' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/account_group' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/account_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/account_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'compromised/account_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/bank_card_group' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/bank_card_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/bank_card_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'compromised/bank_card_group' collection. |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/discord' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/discord' collection. |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/discord' collection. |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'compromised/discord' collection. |
| TI_API_COLLECTIONS_COMPROMISED_IMEI_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/imei' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_IMEI_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/imei' collection. |
| TI_API_COLLECTIONS_COMPROMISED_IMEI_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/imei' collection. |
| TI_API_COLLECTIONS_COMPROMISED_IMEI_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'compromised/imei' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/masked_card' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/masked_card' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/masked_card' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'compromised/masked_card' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/messenger' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/messenger' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/messenger' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'compromised/messenger' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MULE_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'compromised/mule' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_COMPROMISED_MULE_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'compromised/mule' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MULE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'compromised/mule' collection. |
| TI_API_COLLECTIONS_COMPROMISED_MULE_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'compromised/mule' collection. |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'hi/open_threats' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'hi/open_threats' collection. |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'hi/open_threats' collection. |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'hi/open_threats' collection. |
| TI_API_COLLECTIONS_HI_THREAT_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'hi/threat' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_HI_THREAT_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'hi/threat' collection. |
| TI_API_COLLECTIONS_HI_THREAT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'hi/threat' collection. |
| TI_API_COLLECTIONS_HI_THREAT_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'hi/threat' collection. |
| TI_API_COLLECTIONS_HI_THREAT_USE_HUNTING_RULES | `boolean` |  | boolean | `false` | Apply Group-IB hunting rules when importing the 'hi/threat' collection. |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'hi/threat_actor' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'hi/threat_actor' collection. |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'hi/threat_actor' collection. |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'hi/threat_actor' collection. |
| TI_API_COLLECTIONS_IOC_COMMON_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'ioc/common' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_IOC_COMMON_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'ioc/common' collection. |
| TI_API_COLLECTIONS_IOC_COMMON_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'ioc/common' collection. |
| TI_API_COLLECTIONS_IOC_COMMON_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'ioc/common' collection. |
| TI_API_COLLECTIONS_MALWARE_CNC_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'malware/cnc' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_MALWARE_CNC_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'malware/cnc' collection. |
| TI_API_COLLECTIONS_MALWARE_CNC_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'malware/cnc' collection. |
| TI_API_COLLECTIONS_MALWARE_CNC_TTL | `integer` |  | integer | `90` | Time-to-live (in days) for indicators from the 'malware/cnc' collection. |
| TI_API_COLLECTIONS_MALWARE_CONFIG_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'malware/config' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_MALWARE_CONFIG_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'malware/config' collection. |
| TI_API_COLLECTIONS_MALWARE_CONFIG_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'malware/config' collection. |
| TI_API_COLLECTIONS_MALWARE_CONFIG_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'malware/config' collection. |
| TI_API_COLLECTIONS_MALWARE_MALWARE_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'malware/malware' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_MALWARE_MALWARE_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'malware/malware' collection. |
| TI_API_COLLECTIONS_MALWARE_MALWARE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'malware/malware' collection. |
| TI_API_COLLECTIONS_MALWARE_MALWARE_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'malware/malware' collection. |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'malware/signature' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'malware/signature' collection. |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'malware/signature' collection. |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'malware/signature' collection. |
| TI_API_COLLECTIONS_MALWARE_YARA_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'malware/yara' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_MALWARE_YARA_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'malware/yara' collection. |
| TI_API_COLLECTIONS_MALWARE_YARA_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'malware/yara' collection. |
| TI_API_COLLECTIONS_MALWARE_YARA_TTL | `integer` |  | integer | `null` | Time-to-live (in days) for indicators from the 'malware/yara' collection. |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'osi/git_repository' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'osi/git_repository' collection. |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'osi/git_repository' collection. |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'osi/git_repository' collection. |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'osi/public_leak' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'osi/public_leak' collection. |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'osi/public_leak' collection. |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'osi/public_leak' collection. |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'osi/vulnerability' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'osi/vulnerability' collection. |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'osi/vulnerability' collection. |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'osi/vulnerability' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/open_proxy' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'suspicious_ip/open_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'suspicious_ip/open_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_TTL | `integer` |  | integer | `15` | Time-to-live (in days) for indicators from the 'suspicious_ip/open_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/scanner' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'suspicious_ip/scanner' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'suspicious_ip/scanner' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_TTL | `integer` |  | integer | `15` | Time-to-live (in days) for indicators from the 'suspicious_ip/scanner' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/socks_proxy' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'suspicious_ip/socks_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'suspicious_ip/socks_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_TTL | `integer` |  | integer | `2` | Time-to-live (in days) for indicators from the 'suspicious_ip/socks_proxy' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/tor_node' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'suspicious_ip/tor_node' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'suspicious_ip/tor_node' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'suspicious_ip/tor_node' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_DEFAULT_DATE | `string` |  | string | `null` | Start date (YYYY-MM-DD) for the first import of the 'suspicious_ip/vpn' collection; empty means last 3 days. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_ENABLE | `boolean` |  | boolean | `false` | Enable ingestion of the 'suspicious_ip/vpn' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Optional custom label added to objects from the 'suspicious_ip/vpn' collection. |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_TTL | `integer` |  | integer | `30` | Time-to-live (in days) for indicators from the 'suspicious_ip/vpn' collection. |
