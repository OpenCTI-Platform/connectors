# OpenCTI TAXII2 Connector

## Description
This is a generic TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti). It automates the importing of collection(s) from a specified TAXII2 2.0 and 2.1 servers. 


## Configuration
Below are the parameters you'll need to set for OpenCTI:

### OpenCTI
| Docker Env variable | Config.yml | Default | Mandatory | Description |
| ----------|----------|----------|----------|----------|
| OPENCTI_URL | url | http://opencti:8080 | Yes | The URL of the OpenCTI platform. |
| OPENCTI_TOKEN | token | ChangeMe | Yes | The user token set in OpenCTI platform. |

### Connector
| Docker Env variable | Config.yml | Default | Mandatory | Description |
| ----------|----------|----------|----------|----------|
| CONNECTOR_ID | id | ChangeMe | Yes | A unique `UUIDv4` identifier for this connector instance. |
| CONNECTOR_NAME | name | TAXII2_Import | Yes | Name of the connector. |
| CONNECTOR_SCOPE | scope | ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1 | Yes | The scope or type of data the connector is importing. |
| CONNECTOR_LOG_LEVEL | log_level | info | Yes | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| CONNECTOR_DURATION_PERIOD | duration_period | PT60M | Yes | Specifies the execution period duration using the ISO 8601 format. |

### Taxii2
| Docker Env variable | Config.yml | Default | Mandatory | Description |
| ----------|----------|----------|----------|----------|
| TAXII2_DISCOVERY_URL | discovery_url | ChangeMe | Yes | Discovery URL of TAXII2 Server. |
| TAXII2_CERT_PATH | cert_path | | No | Path to certificate. (.pem) |
| TAXII2_USERNAME | username | ChangeMe | No | Username credential to access TAXII Server. |
| TAXII2_PASSWORD | password | ChangeMe | No | Password credential to access TAXII Server. |
| TAXII2_USE_TOKEN | use_token | false | No | Switch from using username and password to using a single token as authentication method. |
| TAXII2_TOKEN | token | ChangeMe | No | Token string from taxii server. |
| TAXII2_USE_APIKEY | use_apikey | false | No | Switch from using username and password to using a key/value pair as authentication method. |
| TAXII2_APIKEY_KEY | apikey | ChangeMe | No | API key - name of the HTTP header. |
| TAXII2_APIKEY_VALUE | apikey_key | ChangeMe | No | The secret value set as the header value. |
| TAXII2_v21 | v2.1 | true | No | Boolean statement to determine if the TAXII Server is V2.0 or V2.1. Defaults to True (V2.1). |
| TAXII2_COLLECTIONS | collections | *.* | No | Specify what TAXII Collections you want to poll. Syntax Detailed below. |
| TAXII2_INITIAL_HISTORY | initial_history | 24 | No | In hours, the "lookback" window for the initial Poll. This will limit the responses only to STIX2 objects that were added to the collection during the specified lookback time. In all subsequent polls, the `interval` or `duration_period` configuration option is used to determine the lookback window. |
| TAXII2_INTERVAL | interval | 1 | Yes | In hours, the amount of time between each run of the connector. This option is being superseded by `duration_period`. |
| VERIFY_SSL | verify_ssl | true | No | Boolean statement on whether to require an SSL/TLS connection with the TAXII Server. |
| TAXII2_CREATE_INDICATORS | create_indicators | true | No | Boolean statement on whether to create indicators. |
| TAXII2_CREATE_OBSERVABLES | create_observables | true | No | Boolean statement on whether to create observables. |
| TAXII2_ADD_CUSTOM_LABEL | add_custom_label | false | No | Boolean statement on whether to add custom label to all indicators. |
| TAXII2_CUSTOM_LABEL | custom_label | ChangeMe | No | String to use for custom label. Requires `add_custom_label` to be configured. |
| TAXII2_FORCE_PATTERN_AS_NAME | force_pattern_as_name | false | No | Boolean statement on whether to force name to be contents of pattern. |
| TAXII2_FORCE_MULTIPLE_PATTERN_NAME | force_multiple_pattern_name | Multiple Indicators | No | String to use for indicators that contain multiple indicators in a single pattern. Requires `force_pattern_as_name` to be configured. |
| TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL | stix_custom_property_to_label | false | No | Boolean statement on whether to create a label from a stix custom property. |
| TAXII2_STIX_CUSTOM_PROPERTY | stix_custom_property | ChangeMe | No | String to match the stix custom property you wish to add as a label e.g. x_category . Requires `stix_custom_property_to_label` to be configured. |
| TAXII2_ENABLE_URL_QUERY_LIMIT | enable_url_query_limit | false | No | Boolean statement on whether to limit the number of responses in a Taxii 2.1 query. |
| TAXII2_URL_QUERY_LIMIT | url_query_limit | 100 | No | The number of responses to limit in a query. Requires `enable_url_query_limit` to be configured. |
| TAXII2_DETERMINE_X_OPENCTI_SCORE_BY_LABEL | determine_x_opencti_score_by_label | false | No | Boolean statement on whether to base the `x_opencti_score` on strings found in labels. |
| TAXII2_DEFAULT_X_OPENCTI_SCORE | default_x_opencti_score | 50 | No | Standard score if string not found. |
| TAXII2_INDICATOR_HIGH_SCORE_LABELS | indicator_high_score_labels | ChangeMe | No | List of strings to match to create a high score e.g. 'high,ransomware'. |
| TAXII2_INDICATOR_HIGH_SCORE | indicator_high_score | 80 | No | Value to use for high score. |
| TAXII2_INDICATOR_MEDIUM_SCORE_LABELS | indicator_medium_score_labels | ChangeMe | No | List of strings to match to create a medium score e.g. medium |
| TAXII2_INDICATOR_MEDIUM_SCORE | indicator_medium_score | 60 | No | Value to use for medium score. |
| TAXII2_INDICATOR_LOW_SCORE_LABELS | indicator_low_score_labels | ChangeMe | No | List of strings to match to create a low score e.g. low |
| TAXII2_INDICATOR_LOW_SCORE | indicator_low_score | 40 | No | Value to use for low score. |
| TAXII2_SET_INDICATOR_AS_DETECTION | set_indicator_as_detection | false | No | Boolean statement on whether to set Detection flag. |
| TAXII2_CREATE_AUTHOR | create_author | false | No | Boolean statement on whether to create an author identity. |
| TAXII2_AUTHOR_NAME | author_name | ChangeMe | No | String to use for author name. |
| TAXII2_AUTHOR_DESCRIPTION | author_description | ChangeMe | No | String to use for author description. |
| TAXII2_AUTHOR_RELIABILITY | author_reliability | A - Completely reliable | No | String to use for author reliability. |
| TAXII2_EXCLUDE_SPECIFIC_LABELS | exclude_specific_labels | false | No | Boolean statement on whether to exclude specific labels that match regex |
| TAXII2_LABELS_TO_EXCLUDE | labels_to_exclude | ChangeMe | No | List of regex to ignore, do not leave empty if exclude_specific_labels TRUE. e.g. 'malware\/,safe:domain' |
| TAXII2_REPLACE_CHARACTERS_IN_LABEL | replace_characters_in_label | false | No | Boolean statement on whether to replace text within a label. |
| TAXII2_CHARACTERS_TO_REPLACE_IN_LABEL | characters_to_replace_in_label | ChangeMe | No | List of strings to find and replace e.g. 'find:replace,malware_family:malware'. |
| TAXII2_IGNORE_PATTERN_TYPES | ignore_pattern_types | false | No | Boolean statement on whether to ignore certain pattern types. |
| TAXII2_PATTERN_TYPES_TO_IGNORE | pattern_types_to_ignore | ChangeMe | No | List of strings which contains the pattern types to ignore. |
| TAXII2_IGNORE_OBJECT_TYPES | ignore_object_types | false | No | Boolean statement on whether to ignore certain object types. |
| TAXII2_OBJECT_TYPES_TO_IGNORE | object_types_to_ignore | ChangeMe | No | List of strings which contains the object types to ignore. |
| TAXII2_IGNORE_SPECIFIC_PATTERNS | ignore_specific_patterns | false | No | Boolean statement on whether to ignore patterns which contain a specific string. |
| TAXII2_PATTERNS_TO_IGNORE | patterns_to_ignore | ChangeMe | No | List of strings which contains the pattern to ignore. |
| TAXII2_IGNORE_SPECIFIC_NOTES | ignore_specific_notes | false | No | Boolean statement on whether to ignore specific notes. |
| TAXII2_NOTES_TO_IGNORE | notes_to_ignore | ChangeMe | No | List of strings which contains a portion of the note to ignore. |
| TAXII2_SAVE_ORIGINAL_INDICATOR_ID_TO_NOTE | save_original_indicator_id_to_note | false | No | Boolean statement on whether to save the original indicator id to a note. |
| TAXII2_SAVE_ORIGINAL_INDICATOR_ID_ABSTRACT | save_original_indicator_id_abstract | ChangeMe | No | String to use for note abstract. |
| TAXII2_CHANGE_REPORT_STATUS | change_report_status | false | No | Boolean statement on whether to change the report status on ingestion. |
| TAXII2_CHANGE_REPORT_STATUS_X_OPENCTI_WORKFLOW_ID | change_report_status_x_opencti_workflow_id | ChangeMe | No | x_opencti_workflow_id value of the report status. |

### Collections and API roots
TAXII 2.0 introduced a new concept into the TAXII standard called an "API Root." API Roots are logical groupings of TAXII Collections and Channels that allow for better organization and federated access. More information can be found in the [TAXII2 standard](https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.pdf)

Unfortunately, the introduction of API Roots makes it more complicated to configure which Collections to poll from. To solve that issue, this connector uses dot notation to specify which collection(s) the user wants to poll, using the format `<API Root>.<Collection Name>`. So if you wanted to poll the `Enterprise ATT&CK` and `Mobile ATT&CK` collections in the API Root `stix` in MITRE's free TAXII2 server, your config variable would like

`stix.Enterprise ATT&CK,stix.Mobile ATT&CK`

Furthermore, this argument supports the use of `*` as a wildcard operator. To Poll all collections in the `STIX` API Root, you could use the syntax `stix.*` If you wanted to poll all collections in the server, you can use the syntax `*.*`

Finally, please note that the "title" of an API Root differs from it's pathing in a URL. For example, the title could be "Malware analysis" whereas the URL for an API Root could just be some_url/malware/. In the Collections parameters, please specify the URL path of an API Root, **not** its title
