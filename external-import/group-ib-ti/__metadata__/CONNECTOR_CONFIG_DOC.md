# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description | Examples |
| -------- | ---- | -------- | --------------- | ------- | ----------- | -------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |  |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The API token to connect to OpenCTI. |  |
| TI_API_USERNAME | `string` | ✅ | string |  | Group-IB TI portal profile email. |  |
| TI_API_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Group-IB TI API token. |  |
| CONNECTOR_NAME | `string` |  | string | `"Group-IB Connector"` | The name of the connector. |  |
| CONNECTOR_SCOPE | `array` |  | string | `["stix2", "report", "threat-actor", "intrusion-set", "malware", "attack-pattern", "vulnerability", "indicator", "location", "identity", "incident", "note", "relationship", "ipv4-addr", "ipv6-addr", "domain", "url", "StixFile", "email-addr", "user-account", "payment-card", "bank-account"]` | The scope of the connector. |  |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |  |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` | `"EXTERNAL_IMPORT"` |  |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"PT4H"` | The period of time to await between two runs of the connector. |  |
| TI_API_URL | `string` |  | string | `"https://tap.group-ib.com/api/v2/"` | Group-IB Threat Intelligence API URL. |  |
| TI_API_PROXY_IP | `string` |  | string | `null` | Proxy host or IP. |  |
| TI_API_PROXY_PORT | `integer` |  | integer | `null` | Proxy port. |  |
| TI_API_PROXY_PROTOCOL | `string` |  | string | `null` | Proxy protocol (http/https). |  |
| TI_API_PROXY_USERNAME | `string` |  | string | `null` | Proxy username. |  |
| TI_API_PROXY_PASSWORD | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `null` | Proxy password. |  |
| TI_API_EXTRA_SETTINGS_INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR | `boolean` |  | boolean | `false` | Emit Intrusion-Set SDOs instead of Threat-Actor. |  |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_MALWARE_DDOS | `boolean` |  | boolean | `false` | Drop DDoS events without a malware payload. |  |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_INDICATOR_THREATS | `boolean` |  | boolean | `false` | Drop threat events carrying no indicators. |  |
| TI_API_EXTRA_SETTINGS_IGNORE_NON_INDICATOR_THREAT_REPORTS | `boolean` |  | boolean | `false` | Drop threat reports carrying no indicators. |  |
| TI_API_EXTRA_SETTINGS_ENABLE_STATEMENT_MARKING | `boolean` |  | boolean | `false` | Attach a Group-IB statement marking to bundles. |  |
| TI_API_EXTRA_SETTINGS_PRESERVE_MANUAL_LABELS | `boolean` |  | boolean | `false` | Omit x_opencti_labels so analyst-added labels survive updates. |  |
| TI_API_EXTRA_SETTINGS_TIME_OUTPUT_FORMAT | `string` |  | string | `null` | strftime format for human-readable timestamps in logs. | ```%Y-%m-%d %H:%M:%S``` |
| TI_API_EXTRA_SETTINGS_ENABLE_FILE_LOGGING | `boolean` |  | boolean | `false` | Write rotating file logs in addition to stdout. |  |
| TI_API_EXTRA_SETTINGS_LOG_FILE_DIR | `string` |  | string | `null` | Directory for rotating file logs. |  |
| TI_API_EXTRA_SETTINGS_LOG_FILE_MAX_BYTES | `integer` |  | integer | `null` | Max size (bytes) per log file before rotation. |  |
| TI_API_EXTRA_SETTINGS_LOG_FILE_BACKUP_COUNT | `integer` |  | integer | `null` | Number of rotated log files to keep. |  |
| TI_API_COLLECTIONS_APT_THREAT_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: apt/threat] | ```2024-01-01``` |
| TI_API_COLLECTIONS_APT_THREAT_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: apt/threat] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_APT_THREAT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_STORE_REPORT_LABELS_IN_NOTE | `boolean` |  | boolean | `null` | Write report labels to a Note instead of the SDO. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_ADD_THREAT_ACTOR_LABEL_TO_OBSERVABLES | `boolean` |  | boolean | `null` | Attach the actor name as a label on observables. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_INCLUDE_THREAT_ACTOR_LABELS | `boolean` |  | boolean | `null` | Add labels naming the linked threat actors. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_INCLUDE_NATION_STATE_LABEL | `boolean` |  | boolean | `null` | Add the global `nation_state` label. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_INCLUDE_CONTEXT_LABEL | `boolean` |  | boolean | `null` | Add labels derived from the payload (tailored, autogen, raw labels). [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_TARGETED_ENTITIES_AS_SDO | `boolean` |  | boolean | `null` | Promote victimology (sectors/regions/companies) into SDOs. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_INCLUDE_EXPERTISE_LABELS | `boolean` |  | boolean | `null` | Add bare expertise labels from the report `expertise` field. [collection: apt/threat] |  |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: apt/threat_actor] |  |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: apt/threat_actor] | ```2024-01-01``` |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: apt/threat_actor] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: apt/threat_actor] |  |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: apt/threat_actor] |  |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_INCLUDE_NATION_STATE_LABEL | `boolean` |  | boolean | `null` | Add the global `nation_state` label. [collection: apt/threat_actor] |  |
| TI_API_COLLECTIONS_APT_THREAT_ACTOR_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: apt/threat_actor] |  |
| TI_API_COLLECTIONS_ATTACKS_DDOS_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: attacks/ddos] |  |
| TI_API_COLLECTIONS_ATTACKS_DDOS_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: attacks/ddos] | ```2024-01-01``` |
| TI_API_COLLECTIONS_ATTACKS_DDOS_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: attacks/ddos] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_ATTACKS_DDOS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: attacks/ddos] |  |
| TI_API_COLLECTIONS_ATTACKS_DDOS_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: attacks/ddos] |  |
| TI_API_COLLECTIONS_ATTACKS_DDOS_CNC_AS_INDICATOR | `boolean` |  | boolean | `null` | Emit CnC observables as Indicators. [collection: attacks/ddos] |  |
| TI_API_COLLECTIONS_ATTACKS_DDOS_CREATE_INCIDENT | `boolean` |  | boolean | `null` | Create an Incident SDO per event. [collection: attacks/ddos] |  |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: attacks/deface] |  |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: attacks/deface] | ```2024-01-01``` |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: attacks/deface] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: attacks/deface] |  |
| TI_API_COLLECTIONS_ATTACKS_DEFACE_CREATE_INCIDENT | `boolean` |  | boolean | `null` | Create an Incident SDO per event. [collection: attacks/deface] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: attacks/phishing_group] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: attacks/phishing_group] | ```2024-01-01``` |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: attacks/phishing_group] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: attacks/phishing_group] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: attacks/phishing_group] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_BRAND_AS_IDENTITY | `boolean` |  | boolean | `null` | Emit the impersonated brand as an Identity. [collection: attacks/phishing_group] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_GROUP_INCLUDE_BRAND_LABELS | `boolean` |  | boolean | `null` | Add bare labels naming the impersonated brands. [collection: attacks/phishing_group] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: attacks/phishing_kit] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: attacks/phishing_kit] | ```2024-01-01``` |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: attacks/phishing_kit] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: attacks/phishing_kit] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: attacks/phishing_kit] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_BRAND_AS_IDENTITY | `boolean` |  | boolean | `null` | Emit the impersonated brand as an Identity. [collection: attacks/phishing_kit] |  |
| TI_API_COLLECTIONS_ATTACKS_PHISHING_KIT_INCLUDE_BRAND_LABELS | `boolean` |  | boolean | `null` | Add bare labels naming the impersonated brands. [collection: attacks/phishing_kit] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/access] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/access] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_DATA_PREVIEW_MAX_LEN | `integer` |  | integer | `null` | Max characters of preview text in Notes when full_data is off. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_FULL_DATA | `boolean` |  | boolean | `null` | Emit full text instead of a truncated preview in Notes. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_CNC_AS_INDICATOR | `boolean` |  | boolean | `null` | Emit CnC observables as Indicators. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCESS_TARGET_OBSERVABLES | `boolean` |  | boolean | `null` | Emit non-IOC target/victim observables. [collection: compromised/access] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/account_group] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/account_group] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_INCLUDE_PASSWORDS | `boolean` |  | boolean | `null` | Include cleartext passwords in the account-group Note (off by default for GDPR / compliance reasons). [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_INCLUDE_MALWARE_LABELS | `boolean` |  | boolean | `null` | Tag entities with the originating malware family name. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_INCLUDE_MALWARE_THREAT_ACTOR_LABELS | `boolean` |  | boolean | `null` | Add labels naming the threat actors linked to the malware. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_INCLUDE_SOURCE_TYPE_LABELS | `boolean` |  | boolean | `null` | Add bare labels from the API `source_type` field. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_UNIQUE | `boolean` |  | boolean | `null` | Upstream API parameter: deduplicate by credential pair. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_COMBOLIST | `boolean` |  | boolean | `null` | Upstream API parameter: include records sourced from combolists (vs. only stealer logs). [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_ACCOUNT_GROUP_PROBABLE_CORPORATE_ACCESS | `boolean` |  | boolean | `null` | Upstream API parameter: prioritise records that look like corporate access. [collection: compromised/account_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/bank_card_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/bank_card_group] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/bank_card_group] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/bank_card_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_BANK_CARD_GROUP_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: compromised/bank_card_group] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/discord] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/discord] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_REDACT_MESSAGE_TEXT | `boolean` |  | boolean | `null` | Omit the raw chat message body from the Note (keep metadata). [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_INCLUDE_TRANSLATION_IN_NOTE | `boolean` |  | boolean | `null` | Append the message translation (when present) to the Note. [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_FULL_DATA | `boolean` |  | boolean | `null` | Emit full text instead of a truncated preview in Notes. [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_DISCORD_DATA_PREVIEW_MAX_LEN | `integer` |  | integer | `null` | Max characters of preview text in Notes when full_data is off. [collection: compromised/discord] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/masked_card] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/masked_card] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_INCLUDE_MALWARE_LABELS | `boolean` |  | boolean | `null` | Tag entities with the originating malware family name. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_INCLUDE_THREAT_ACTOR_LABELS | `boolean` |  | boolean | `null` | Add labels naming the linked threat actors. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MASKED_CARD_INCLUDE_SOURCE_TYPE_LABELS | `boolean` |  | boolean | `null` | Add bare labels from the API `source_type` field. [collection: compromised/masked_card] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/messenger] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/messenger] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_REDACT_MESSAGE_TEXT | `boolean` |  | boolean | `null` | Omit the raw chat message body from the Note (keep metadata). [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_INCLUDE_TRANSLATION_IN_NOTE | `boolean` |  | boolean | `null` | Append the message translation (when present) to the Note. [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_FULL_DATA | `boolean` |  | boolean | `null` | Emit full text instead of a truncated preview in Notes. [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_MESSENGER_DATA_PREVIEW_MAX_LEN | `integer` |  | integer | `null` | Max characters of preview text in Notes when full_data is off. [collection: compromised/messenger] |  |
| TI_API_COLLECTIONS_COMPROMISED_SPD_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: compromised/spd] |  |
| TI_API_COLLECTIONS_COMPROMISED_SPD_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: compromised/spd] | ```2024-01-01``` |
| TI_API_COLLECTIONS_COMPROMISED_SPD_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: compromised/spd] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_COMPROMISED_SPD_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: compromised/spd] |  |
| TI_API_COLLECTIONS_COMPROMISED_SPD_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: compromised/spd] |  |
| TI_API_COLLECTIONS_DARKWEB_FORUMS_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: darkweb/forums] |  |
| TI_API_COLLECTIONS_DARKWEB_FORUMS_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: darkweb/forums] | ```2024-01-01``` |
| TI_API_COLLECTIONS_DARKWEB_FORUMS_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: darkweb/forums] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_DARKWEB_FORUMS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: darkweb/forums] |  |
| TI_API_COLLECTIONS_DARKWEB_FORUMS_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: darkweb/forums] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: hi/open_threats] | ```2024-01-01``` |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: hi/open_threats] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_DATA_PREVIEW_MAX_LEN | `integer` |  | integer | `null` | Max characters of preview text in Notes when full_data is off. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_FULL_DATA | `boolean` |  | boolean | `null` | Emit full text instead of a truncated preview in Notes. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_INCLUDE_TEXT_IN_NOTE | `boolean` |  | boolean | `null` | Include the parsed text body in the Note. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_INCLUDE_ORIGINAL_IN_NOTE | `boolean` |  | boolean | `null` | Include the raw original payload in the Note. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_OPEN_THREATS_OBSERVABLES_AS_INDICATORS | `boolean` |  | boolean | `null` | Emit report IOC observables as Indicators. [collection: hi/open_threats] |  |
| TI_API_COLLECTIONS_HI_THREAT_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: hi/threat] | ```2024-01-01``` |
| TI_API_COLLECTIONS_HI_THREAT_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: hi/threat] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_HI_THREAT_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_STORE_REPORT_LABELS_IN_NOTE | `boolean` |  | boolean | `null` | Write report labels to a Note instead of the SDO. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_ADD_THREAT_ACTOR_LABEL_TO_OBSERVABLES | `boolean` |  | boolean | `null` | Attach the actor name as a label on observables. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_INCLUDE_THREAT_ACTOR_LABELS | `boolean` |  | boolean | `null` | Add labels naming the linked threat actors. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_INCLUDE_CYBERCRIMINAL_LABEL | `boolean` |  | boolean | `null` | Add the global `cybercriminal` label. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_INCLUDE_CONTEXT_LABEL | `boolean` |  | boolean | `null` | Add labels derived from the payload (tailored, autogen, raw labels). [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_TARGETED_ENTITIES_AS_SDO | `boolean` |  | boolean | `null` | Promote victimology (sectors/regions/companies) into SDOs. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_INCLUDE_EXPERTISE_LABELS | `boolean` |  | boolean | `null` | Add bare expertise labels from the report `expertise` field. [collection: hi/threat] |  |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: hi/threat_actor] |  |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: hi/threat_actor] | ```2024-01-01``` |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: hi/threat_actor] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: hi/threat_actor] |  |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: hi/threat_actor] |  |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_INCLUDE_CYBERCRIMINAL_LABEL | `boolean` |  | boolean | `null` | Add the global `cybercriminal` label. [collection: hi/threat_actor] |  |
| TI_API_COLLECTIONS_HI_THREAT_ACTOR_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: hi/threat_actor] |  |
| TI_API_COLLECTIONS_IOC_PRIMARY_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: ioc/primary] |  |
| TI_API_COLLECTIONS_IOC_PRIMARY_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: ioc/primary] | ```2024-01-01``` |
| TI_API_COLLECTIONS_IOC_PRIMARY_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: ioc/primary] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_IOC_PRIMARY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: ioc/primary] |  |
| TI_API_COLLECTIONS_MALWARE_CNC_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: malware/cnc] |  |
| TI_API_COLLECTIONS_MALWARE_CNC_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: malware/cnc] | ```2024-01-01``` |
| TI_API_COLLECTIONS_MALWARE_CNC_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: malware/cnc] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_MALWARE_CNC_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: malware/cnc] |  |
| TI_API_COLLECTIONS_MALWARE_CNC_INCLUDE_MALWARE_LABELS | `boolean` |  | boolean | `null` | Tag entities with the originating malware family name. [collection: malware/cnc] |  |
| TI_API_COLLECTIONS_MALWARE_CNC_INCLUDE_THREAT_ACTOR_LABELS | `boolean` |  | boolean | `null` | Add labels naming the linked threat actors. [collection: malware/cnc] |  |
| TI_API_COLLECTIONS_MALWARE_CNC_ALL_OBSERVABLES_AS_INDICATORS | `boolean` |  | boolean | `null` | Emit every observable of the event as an Indicator. [collection: malware/cnc] |  |
| TI_API_COLLECTIONS_MALWARE_CONFIG_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: malware/config] |  |
| TI_API_COLLECTIONS_MALWARE_CONFIG_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: malware/config] | ```2024-01-01``` |
| TI_API_COLLECTIONS_MALWARE_CONFIG_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: malware/config] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_MALWARE_CONFIG_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: malware/config] |  |
| TI_API_COLLECTIONS_MALWARE_CONFIG_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: malware/config] |  |
| TI_API_COLLECTIONS_MALWARE_CONFIG_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: malware/config] |  |
| TI_API_COLLECTIONS_MALWARE_CONFIG_INCLUDE_MALWARE_LABELS | `boolean` |  | boolean | `null` | Tag entities with the originating malware family name. [collection: malware/config] |  |
| TI_API_COLLECTIONS_MALWARE_MALWARE_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: malware/malware] |  |
| TI_API_COLLECTIONS_MALWARE_MALWARE_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: malware/malware] | ```2024-01-01``` |
| TI_API_COLLECTIONS_MALWARE_MALWARE_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: malware/malware] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_MALWARE_MALWARE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: malware/malware] |  |
| TI_API_COLLECTIONS_MALWARE_MALWARE_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: malware/malware] |  |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: malware/signature] |  |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: malware/signature] | ```2024-01-01``` |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: malware/signature] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_MALWARE_SIGNATURE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: malware/signature] |  |
| TI_API_COLLECTIONS_MALWARE_YARA_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: malware/yara] |  |
| TI_API_COLLECTIONS_MALWARE_YARA_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: malware/yara] | ```2024-01-01``` |
| TI_API_COLLECTIONS_MALWARE_YARA_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: malware/yara] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_MALWARE_YARA_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: malware/yara] |  |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: osi/git_repository] |  |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: osi/git_repository] | ```2024-01-01``` |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: osi/git_repository] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: osi/git_repository] |  |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: osi/git_repository] |  |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: osi/git_repository] |  |
| TI_API_COLLECTIONS_OSI_GIT_REPOSITORY_AUTHOR_EMAIL_OBSERVABLES | `boolean` |  | boolean | `null` | Emit commit-author emails as observables. [collection: osi/git_repository] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: osi/public_leak] | ```2024-01-01``` |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: osi/public_leak] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_DATA_PREVIEW_MAX_LEN | `integer` |  | integer | `null` | Max characters of preview text in Notes when full_data is off. [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_FULL_DATA | `boolean` |  | boolean | `null` | Emit full text instead of a truncated preview in Notes. [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_PUBLIC_LEAK_DESCRIPTION_IN_EXTERNAL_REFERENCES | `boolean` |  | boolean | `null` | Move the entity description into an external reference instead of the SDO description field. [collection: osi/public_leak] |  |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: osi/vulnerability] |  |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: osi/vulnerability] | ```2024-01-01``` |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: osi/vulnerability] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: osi/vulnerability] |  |
| TI_API_COLLECTIONS_OSI_VULNERABILITY_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: osi/vulnerability] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: suspicious_ip/open_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: suspicious_ip/open_proxy] | ```2024-01-01``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: suspicious_ip/open_proxy] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: suspicious_ip/open_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_OPEN_PROXY_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: suspicious_ip/open_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: suspicious_ip/scanner] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: suspicious_ip/scanner] | ```2024-01-01``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: suspicious_ip/scanner] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: suspicious_ip/scanner] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SCANNER_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: suspicious_ip/scanner] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: suspicious_ip/socks_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: suspicious_ip/socks_proxy] | ```2024-01-01``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: suspicious_ip/socks_proxy] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: suspicious_ip/socks_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_SOCKS_PROXY_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: suspicious_ip/socks_proxy] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: suspicious_ip/tor_node] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: suspicious_ip/tor_node] | ```2024-01-01``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: suspicious_ip/tor_node] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: suspicious_ip/tor_node] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_TOR_NODE_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: suspicious_ip/tor_node] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_ENABLE | `boolean` |  | boolean | `false` | Ingest this collection. Must be true to run. [collection: suspicious_ip/vpn] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_DEFAULT_DATE | `string` |  | string | `null` | First-run lookback anchor (YYYY-MM-DD). Ignored after the stored sequpdate cursor takes over. [collection: suspicious_ip/vpn] | ```2024-01-01``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_TTL | `integer` |  | integer | `null` | Validity period (days) for emitted Indicator SDOs. [collection: suspicious_ip/vpn] | ```30```, ```90```, ```1460``` |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_LOCAL_CUSTOM_TAG | `string` |  | string | `null` | Extra bare label appended to every entity from this collection. [collection: suspicious_ip/vpn] |  |
| TI_API_COLLECTIONS_SUSPICIOUS_IP_VPN_USE_HUNTING_RULES | `boolean` |  | boolean | `null` | Ask the Group-IB API to apply portal hunting rules server-side (only honored by collections that support it). [collection: suspicious_ip/vpn] |  |
