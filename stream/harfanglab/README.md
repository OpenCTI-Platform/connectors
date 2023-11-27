# OpenCTI HarfangLab Connector

This connector allows organizations to feed the HarfangLab EDR using OpenCTI knowledge.

This connector leverages the OpenCTI events stream, so it consumes knowledge in real time and, depending on its settings, create detection and hunting intel pieces in the HarfangLab platform.

## General overview

OpenCTI data is coming from import connectors. Once this data is ingested in OpenCTI, it is pushed to a Redis event stream. This stream is consumed by the HarfangLab connector to insert intel in the HarfangLab platform.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0
- HarfangLab Threat Response >= 2.X.X
- pycti >= 5.X.X
- stix-shifter >= 6.X.X
- stix-shifter-utils >= 6.X.X
- stix-shifter-modules-splunk >= 6.X.X


| Parameter                                             | Docker envvar                                         | Mandatory | Description                                                                                                                   |
|-------------------------------------------------------|-------------------------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                                         | `OPENCTI_URL`                                         | Yes       | The URL of the OpenCTI platform.                                                                                              |
| `opencti_token`                                       | `OPENCTI_TOKEN`                                       | Yes       | The token of the OpenCTI user (it's recommanded to create a dedicated user for the connector with the Administrator role).    |
| `connector_id`                                        | `CONNECTOR_ID`                                        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                            |
| `connector_type`                                      | `CONNECTOR_TYPE`                                      | Yes       | Must be `STREAM` (this is the connector type).                                                                                |
| `connector_live_stream_id`                            | `CONNECTOR_LIVE_STREAM_ID`                            | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.                                                            |
| `connector_live_stream_listen_delete`                 | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`                 | Yes       | The Live Stream listen delete must be `true`.                                                                                 |
| `connector_live_stream_no_dependencies`               | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`               | Yes       | The Live Stream no dependencies must be `false` because it's necessary to detect observables in the stream.                   |
| `connector_name`                                      | `CONNECTOR_NAME`                                      | Yes       | The name of the HarfangLab instance, to identify it if you have multiple HarfangLab connectors.                               |
| `connector_scope`                                     | `CONNECTOR_SCOPE`                                     | Yes       | Must be `harfanglab`, not used in this connector.                                                                             |
| `connector_confidence_level`                          | `CONNECTOR_CONFIDENCE_LEVEL`                          | Yes       | The default confidence level for created sightings.                                                                           |
| `connector_log_level`                                 | `CONNECTOR_LOG_LEVEL`                                 | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                 |
| `harfanglab_url`                                      | `HARFANGLAB_URL`                                      | Yes       | The HarfangLab instance URL.                                                                                                  |
| `harfanglab_ssl_verify`                               | `HARFANGLAB_SSL_VERIFY`                               | Yes       | Enable the SSL certificate check (default: `true`).                                                                           |
| `harfanglab_token`                                    | `HARFANGLAB_TOKEN`                                    | Yes       | The token of the HarfangLab user.                                                                                             |
| `harfanglab_login`                                    | `HARFANGLAB_LOGIN`                                    | Yes       | The HarfangLab login user.                                                                                                    |
| `harfanglab_password`                                 | `HARFANGLAB_PASSWORD`                                 | Yes       | The HarfangLab password.                                                                                                      |
| `harfanglab_source_list_name`                         | `HARFANGLAB_SOURCE_LIST_NAME`                         | Yes       | Must be `from_OpenCTI`.                                                                                                       |
| `harfanglab_remove_indicator`                         | `HARFANGLAB_REMOVE_INDICATOR`                         | Yes       | Choose between permanent deletion or deactivation of indicators in the HarfangLab platform (default: `true`).                 |
| `harfanglab_rule_maturity`                            | `HARFANGLAB_RULE_MATURITY`                            | Yes       | Allows you to create rules with the `stable` or `testing` status in HarfangLab platform.                                      |
| `harfanglab_import_security_events_as_incidents`      | `HARFANGLAB_IMPORT_SECURITY_EVENTS_AS_INCIDENTS`      | Yes       | Import security events as incidents, from HarfangLab to openCTI. (default: `true`)                                            |
| `harfanglab_import_threads_as_case_incidents`         | `HARFANGLAB_IMPORT_THREADS_AS_CASE_INCIDENTS`         | Yes       | Import threads as case incidents, from HarfangLab to openCTI. If `true`, "import security events as sightings" must be `true` |
| `harfanglab_import_security_events_filters_by_status` | `HARFANGLAB_IMPORT_SECURITY_EVENTS_FILTERS_BY_STATUS` | Yes       | Filters available : new, investigating, false_positive, closed - example : 'new, investigating'                               |
| `harfanglab_import_filters_by_alert_type`             | `HARFANGLAB_IMPORT_FILTERS_BY_ALERT_TYPE`             | Yes       | Filters available : yara, sigma, ioc - example : 'sigma, ioc'                                                                 |
| `harfanglab_default_markings`                         | `HARFANGLAB_DEFAULT_MARKINGS`                         | Yes       | Choose one marking by default. Markings available : TLP:CLEAR - TLP:GREEN - TLP:AMBER - TLP:RED                               |

## Launch the connector and test it

After launching the connector, you should see a new source list for Yara / Sigma / IoC within the HarfangLab platform under "Threat Intelligence" :

![source.png](doc/source.png)