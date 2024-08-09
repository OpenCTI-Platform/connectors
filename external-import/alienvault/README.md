# OpenCTI AlienVault Connector

The OpenCTI AlienVault connector can be used to import knowledge from the Alien Labs Open Threat Exchange (OTX) platform.
The connector leverages the OTX DirectConnect API to get the threat data of the subscribed pulses.

**Note**: Requires joining the OTX threat intelligence community.

## Installation

The OpenCTI AlienVault connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-alienvault:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `OpenCTI` | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------------|------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |
 
Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml          | Docker environment variable   | Default      | Mandatory | Description                                                                                      |
|-----------------------|---------------------|-------------------------------|--------------|-----------|--------------------------------------------------------------------------------------------------|
| ID                    | `id`                | `CONNECTOR_ID`                | /            | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Name                  | `name`              | `CONNECTOR_NAME`              | `AlienVault` | Yes       | Full name of the connector : `AlienVault`.                                                       |
| Scope                 | `scope`             | `CONNECTOR_SCOPE`             | `alienvault` | Yes       | Must be `alienvault`, not used in this connector.                                                |
| Run and Terminate     | `run_and_terminate` | `CONNECTOR_RUN_AND_TERMINATE` | `False`      | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`.           |
| Duration Period       | `duration_period`   | `CONNECTOR_DURATION_PERIOD`   | /            | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT30M`.      |
| Queue Threshold       | `queue_threshold`   | `CONNECTOR_QUEUE_THRESHOLD`   | `500`        | No        | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode. |
| Log Level             | `log_level`         | `CONNECTOR_LOG_LEVEL`         | /            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |

Below are the parameters you'll need to set for AlienVault connector:

| Parameter `AlienVault`           | config.yml                         | Docker environment variable                   | Default                       | Mandatory | Description                                                                                                                    |
|----------------------------------|------------------------------------|-----------------------------------------------|-------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|
| Base Url                         | `base_url`                         | `ALIENVAULT_BASE_URL`                         | `https://otx.alienvault.com`  | Yes       | The base URL for the OTX DirectConnect API.                                                                                    |
| Api Key                          | `api_key`                          | `ALIENVAULT_API_KEY`                          | `ChangeMe`                    | No        | The OTX Key.                                                                                                                   |
| TLP                              | `tlp`                              | `ALIENVAULT_TLP`                              | `White`                       | Yes       | The default TLP marking used if the Pulse does not define TLP.                                                                 |
| Create Observables               | `create_observables`               | `ALIENVAULT_CREATE_OBSERVABLES`               | `True`                        | No        | If true then observables will be created from Pulse indicators and added to the report.                                        |
| Create Indicators                | `create_indicators`                | `ALIENVAULT_CREATE_INDICATORS`                | `True`                        | No        | If true then indicators will be created from Pulse indicators and added to the report.                                         |
| Pulse Start Timestamp            | `pulse_start_timestamp`            | `ALIENVAULT_PULSE_START_TIMESTAMP`            | `2020-05-01T00:00:00`         | Yes       | The Pulses modified after this timestamp will be imported. Timestamp in ISO 8601 format, UTC.                                  |
| Report Status                    | `report_status`                    | `ALIENVAULT_REPORT_STATUS`                    | `New`                         | Yes       | The status of imported reports in the OpenCTI.                                                                                 |
| Report Type                      | `report_type`                      | `ALIENVAULT_REPORT_TYPE`                      | `threat-report`               | No        | The type of imported reports in the OpenCTI.                                                                                   |
| Guess Malware                    | `guess_malware`                    | `ALIENVAULT_GUESS_MALWARE`                    | `False`                       | Yes       | The Pulse tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Pulse.                        |
| Guess CVE                        | `guess_cve`                        | `ALIENVAULT_GUESS_CVE`                        | `False`                       | Yes       | The Pulse tags are used to guess (checks whether tag matches (CVE-\d{4}-\d{4,7})) vulnerabilities.                             |
| Excluded Pulse Indicator Types   | `excluded_pulse_indicator_types`   | `ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES`   | `FileHash-MD5,FileHash-SHA1`  | Yes       | The Pulse indicator types that will be excluded from the import.                                                               |
| Enable Relationships             | `enable_relationships`             | `ALIENVAULT_ENABLE_RELATIONSHIPS`             | `True`                        | No        | If true then the relationships will be created between SDOs.                                                                   |
| Enable Attack Patterns Indicates | `enable_attack_patterns_indicates` | `ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES` | `True`                        | No        | If true then the relationships `indicates` will be created between indicators and attack patterns.                             |
| Filter Indicators                | `filter_indicators`                | `ALIENVAULT_FILTER_INDICATORS`                | `True`                        | No        | This boolean filters out indicators created before the latest pulse datetime, ensuring only recent indicators are processed.   |

