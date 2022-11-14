# OpenCTI CrowdStrike Connector

The OpenCTI CrowdStrike connector can be used to import knowledge from the CrowdStrike
Falcon platform. The connector leverages the Intel APIs to get information about
CrowdStrike’s intelligence, including data about actors, indicators, reports, and YARA
rules.

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the connector.

## Installation

The OpenCTI CrowdStrike connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-crowdstrike:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

The connector can be configured with the following variables:

| Config Parameter             | Docker env var                           | Default                                             | Description                                                                                               |
| ---------------------------- | ---------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `base_url`                   | `CROWDSTRIKE_BASE_URL`                   | `https://api.crowdstrike.com`                       | The base URL for the CrowdStrike APIs.                                                                    |
| `client_id`                  | `CROWDSTRIKE_CLIENT_ID`                  | `ChangeMe`                                          | The CrowdStrike API client ID.                                                                            |
| `client_secret`              | `CROWDSTRIKE_CLIENT_SECRET`              | `ChangeMe`                                          | The CrowdStrike API client secret.                                                                        |
| `tlp`                        | `CROWDSTRIKE_TLP`                        | `Amber`                                             | The TLP marking used for the imported objects in the OpenCTI.                                             |
| `create_observables`         | `CROWDSTRIKE_CREATE_OBSERVABLES`         | `true`                                              | If true then observables will be created from the CrowdStrike indicators.                                 |
| `create_indicators`          | `CROWDSTRIKE_CREATE_INDICATORS`          | `true`                                              | If true then indicators will be created from the CrowdStrike indicators.                                  |
| `scopes`                     | `CROWDSTRIKE_SCOPES`                     | `actor,report,indicator,yara_master,snort_suricata_master`                | The scopes defines what data will be imported from the CrowdStrike.                                       |
| `actor_start_timestamp`      | `CROWDSTRIKE_ACTOR_START_TIMESTAMP`      | `0`                                                 | The Actors created after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.              |
| `report_start_timestamp`     | `CROWDSTRIKE_REPORT_START_TIMESTAMP`     | `0`                                                 | The Reports created after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.             |
| `report_status`              | `CROWDSTRIKE_REPORT_STATUS`              | `New`                                               | The status of imported reports in the OpenCTI.                                                            |
| `report_include_types`       | `CROWDSTRIKE_REPORT_INCLUDE_TYPES`       | `notice,tipper,intelligence report,periodic report` | The types of Reports included in the import. The types are defined by the CrowdStrike.                    |
| `report_type`                | `CROWDSTRIKE_REPORT_TYPE`                | `Threat Report`                                     | The type of imported reports in the OpenCTI.                                                              |
| `report_guess_malware`       | `CROWDSTRIKE_REPORT_GUESS_MALWARE`       | `false`                                             | The Report tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Report. |
| `indicator_start_timestamp`  | `CROWDSTRIKE_INDICATOR_START_TIMESTAMP`  | `0`                                                 | The Indicators published after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.        |
| `indicator_exclude_types`    | `CROWDSTRIKE_INDICATOR_EXCLUDE_TYPES`    | `hash_ion,hash_md5,hash_sha1`                       | The types of Indicators excluded from the import. The types are defined by the CrowdStrike.               |
| `indicator_low_score`        | `CROWDSTRIKE_INDICATOR_LOW_SCORE`        | `40`                                                | If any of the low score labels are found on the indicator then this value is used as a score.             |
| `indicator_low_score_labels` | `CROWDSTRIKE_INDICATOR_LOW_SCORE_LABELS` | `MaliciousConfidence/Low`                           | The labels used to determine the low score indicators.                                                    |
| `interval_sec`               | `CROWDSTRIKE_INTERVAL_SEC`               | `1800`                                              | The import interval in seconds.                                                                           |

**Note**: It is not recommended to use the default value `0` for configuration parameters `report_start_timestamp` and `indicator_start_timestamp` because of the large data volumes.
