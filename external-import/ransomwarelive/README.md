# RansomwareLive Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Installation

### Requirements

- OpenCTI Platform >= 6.6.17

### Configuration

Configuration parameters are provided using environment variables as described below.
Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.

Note that the values that follow can be grabbed within Python code using `self.helper.{PARAMETER}` i.e., `self.helper.connector_name`.

Expected environment variables to be set in the  `docker-compose.yml` that describe the connector itself.
Most of the time, these values are NOT expected to be changed.

| Parameter       | config.yml | Docker environment variable  | Mandatory | Description                              |
|-----------------|------------|------------------------------|-----------|------------------------------------------|
| Connector Name  | `name`     | `CONNECTOR_NAME`             | Yes       | A connector name to be shown in OpenCTI. |                                                                                                                   |
| Connector Scope | `scope`    | `CONNECTOR_SCOPE`            | Yes       | Supported scope. E. g., `text/html`.     |

However, there are other values which are expected to be configured by end users.
The following values are expected to be defined in the `.env` file.
This file is included in the `.gitignore` to avoid leaking sensitive date. 
Note that the `.env.sample` file can be used as a reference.

The ones that follow are connector's generic execution parameters expected to be added for export connectors.

| Parameter                   | config.yml        | Docker environment variable  | Default | Mandatory | Description                                                                                                                                                                   |
|-----------------------------|-------------------|------------------------------|---------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OpenCTI URL                 | `url`             | `OPENCTI_URL`                |         | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                  |
| OpenCTI Token               | `token`           | `OPENCTI_TOKEN`              |         | Yes       | The API token for authenticating with OpenCTI.                                                                                                                                |
| Connector ID                | `id`              | `CONNECTOR_ID`               |         | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                            |
| Connector Scope             | `log_level`       | `CONNECTOR_LOG_LEVEL`        | error   | No        | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                 |
| Duration period             | `duration_period` | `CONNECTOR_DURATION_PERIOD`  |         | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: PT30M.                                                                                     |
| ~~Interval~~ ⚠️Deprecated   | ~~/~~             | ~~`CONNECTOR_RUN_EVERY`~~    | ~~10m~~ | ~~❌~~     | The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., 30s is 30 seconds. 1d is 1 day. |


Finally, the ones that follow are connector's specific execution parameters expected to be used by this connector.

| Parameter                 | config.yml            | Docker environment variable      | Default | Mandatory | Description                                              |
|---------------------------|-----------------------|----------------------------------|---------|-----------|----------------------------------------------------------|
| Pull History              | `pull_history`        | `RANSOMWARE_PULL_HISTORY`        | False   | No        | Whether to pull historic data (Default: false)           |
| History Start Year        | `history_start_year`  | `RANSOMWARE_HISTORY_START_YEAR`  | 2023    | No        | The year to start from (Default: 2020)                   |
| Create Threat Actor       | `create_threat_actor` | `RANSOMWARE_CREATE_THREAT_ACTOR` | False   | No        | Whether to create a Threat Actor object (Default: false) |

### Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information


<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
