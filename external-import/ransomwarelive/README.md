# RansomwareLive Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-07-25 |    -    |

## Installation

### Requirements

- OpenCTI Platform >= 6.7.19

### Configuration

Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.

Note that the values that follow can be grabbed within Python code using `self.helper.{PARAMETER}` i.e., `self.helper.connector_name`.

Expected environment variables to be set in the  `docker-compose.yml` that describe the connector itself. |

However, there are other values which are expected to be configured by end users.
The values that are expected have to be defined in the `.env` file.
This file is included in the `.gitignore` to avoid leaking sensitive date. 
Note that the `.env.sample` file can be used as a reference.

The ones that follow are connector's specific execution parameters expected to be used by this connector.

| Parameter                 | .env variable         | Docker environment variable     |
|---------------------------|-----------------------|---------------------------------|
| Pull History              | `pull_history`        | `CONNECTOR_PULL_HISTORY`        |
| History Start Year        | `history_start_year`  | `CONNECTOR_HISTORY_START_YEAR`  |
| Create Threat Actor       | `create_threat_actor` | `CONNECTOR_CREATE_THREAT_ACTOR` | 

## Configuration variables

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)


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
