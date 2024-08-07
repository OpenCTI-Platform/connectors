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

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `OpenCTI` | config.yml  | Docker environment variable | Mandatory | Description                                          |
|---------------------|-------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`       | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`     | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml          | Docker environment variable   | Default | Mandatory | Example                                | Description                                                                                      |
|-----------------------|---------------------|-------------------------------|---------|-----------|----------------------------------------|--------------------------------------------------------------------------------------------------|
| ID                    | `id`                | `CONNECTOR_ID`                | /       | Yes       | `fe418972-1b42-42c9-a665-91544c1a9939` | A unique `UUIDv4` identifier for this connector instance.                                        |
| Name                  | `name`              | `CONNECTOR_NAME`              | /       | Yes       | `CrowdStrike`                          | Full name of the connector : `CrowdStrike`.                                                      |
| Scope                 | `scope`             | `CONNECTOR_SCOPE`             | /       | Yes       | `crowdStrike`                          | Must be `crowdStrike`, not used in this connector.                                               |
| Run and Terminate     | `run_and_terminate` | `CONNECTOR_RUN_AND_TERMINATE` | `False` | No        | /                                      | Launch the connector once if set to True. Takes 2 available values: `True` or `False`.           |
| Duration Period       | `duration_period`   | `CONNECTOR_DURATION_PERIOD`   | /       | Yes       | `PT30M`                                | Determines the time interval between each launch of the connector in ISO 8601, ex: .             |
| Queue Threshold       | `queue_threshold`   | `CONNECTOR_QUEUE_THRESHOLD`   | `500`   | No        | /                                      | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode. |
| Log Level             | `log_level`         | `CONNECTOR_LOG_LEVEL`         | /       | Yes       | `error`                                | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |

Below are the parameters you'll need to set for CrowdStrike Connector:

| Parameter `CrowdStrike`     | config.yml                   | Docker environment variable              | Default                       | Mandatory  | Example                                                    | Description                                                                                               |
|-----------------------------|------------------------------|------------------------------------------|-------------------------------|------------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Base Url                    | `base_url`                   | `CROWDSTRIKE_BASE_URL`                   | `https://api.crowdstrike.com` | No         | /                                                          | The base URL for the CrowdStrike APIs.                                                                    |
| Client ID                   | `client_id`                  | `CROWDSTRIKE_CLIENT_ID`                  | `ChangeMe`                    | Yes        | `ChangeMe`                                                 | The CrowdStrike API client ID.                                                                            |
| Client Secret               | `client_secret`              | `CROWDSTRIKE_CLIENT_SECRET`              | `ChangeMe`                    | Yes        | `ChangeMe`                                                 | The CrowdStrike API client secret.                                                                        |
| TLP                         | `tlp`                        | `CROWDSTRIKE_TLP`                        | `Amber`                       | No         | /                                                          | The TLP marking used for the imported objects in the OpenCTI.                                             |
| Create Observables          | `create_observables`         | `CROWDSTRIKE_CREATE_OBSERVABLES`         | /                             | Yes        | `true`                                                     | If true then observables will be created from the CrowdStrike indicators.                                 |
| Create Indicators           | `create_indicators`          | `CROWDSTRIKE_CREATE_INDICATORS`          | /                             | Yes        | `true`                                                     | If true then indicators will be created from the CrowdStrike indicators.                                  |
| Scopes                      | `scopes`                     | `CROWDSTRIKE_SCOPES`                     | /                             | Yes        | `actor,report,indicator,yara_master,snort_suricata_master` | The scopes defines what data will be imported from the CrowdStrike.                                       |
| Actor Start Timestamp       | `actor_start_timestamp`      | `CROWDSTRIKE_ACTOR_START_TIMESTAMP`      | /                             | Yes        | `0`                                                        | The Actors created after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.              |
| Report Start Timestamp      | `report_start_timestamp`     | `CROWDSTRIKE_REPORT_START_TIMESTAMP`     | /                             | Yes        | `0`                                                        | The Reports created after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.             |
| Report Status               | `report_status`              | `CROWDSTRIKE_REPORT_STATUS`              | /                             | Yes        | `New`                                                      | The status of imported reports in the OpenCTI.                                                            |
| Report Include Types        | `report_include_types`       | `CROWDSTRIKE_REPORT_INCLUDE_TYPES`       | /                             | Yes        | `notice,tipper,intelligence report,periodic report`        | The types of Reports included in the import. The types are defined by the CrowdStrike.                    |
| Report Type                 | `report_type`                | `CROWDSTRIKE_REPORT_TYPE`                | /                             | Yes        | `Threat Report`                                            | The type of imported reports in the OpenCTI.                                                              |
| Report Guess Malware        | `report_guess_malware`       | `CROWDSTRIKE_REPORT_GUESS_MALWARE`       | /                             | Yes        | `false`                                                    | The Report tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Report. |
| Indicator Start Timestamp   | `indicator_start_timestamp`  | `CROWDSTRIKE_INDICATOR_START_TIMESTAMP`  | /                             | Yes        | `0`                                                        | The Indicators published after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.        |
| Indicator Exclude Types     | `indicator_exclude_types`    | `CROWDSTRIKE_INDICATOR_EXCLUDE_TYPES`    | /                             | Yes        | `hash_ion,hash_md5,hash_sha1`                              | The types of Indicators excluded from the import. The types are defined by the CrowdStrike.               |
| Indicator Low Score         | `indicator_low_score`        | `CROWDSTRIKE_INDICATOR_LOW_SCORE`        | /                             | Yes        | `40`                                                       | If any of the low score labels are found on the indicator then this value is used as a score.             |
| Indicator Low Score Labels  | `indicator_low_score_labels` | `CROWDSTRIKE_INDICATOR_LOW_SCORE_LABELS` | /                             | Yes        | `MaliciousConfidence/Low` or `MaliciousConfidence/Medium`  | The labels used to determine the low score indicators.                                                    |
| Indicator Unwanted Labels   | `indicator_unwanted_labels`  | `CROWDSTRIKE_INDICATOR_UNWANTED_LABELS`  | /                             | No         | /                                                          | Indicators to be excluded from import based on the labels affixed to them.                                |

**Note**: It is not recommended to use the default value `0` for configuration parameters `report_start_timestamp` and `indicator_start_timestamp` because of the large data volumes.
