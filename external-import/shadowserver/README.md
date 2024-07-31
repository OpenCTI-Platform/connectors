# Shadowserver Connector

The integration uses Shadowservers reports API to query the available Shadowserver reports and transform them into Stix objects making them available within OpenCTI. All available reports are downloaded and an `Artifact` object is created with the original file. Stix `Note` objects are added to both the `Report` and the `CustomObjectCaseIncident` with a mark-down rendition of each finding from the report.

API and report references from The Shadowserver Foundation
 - https://github.com/The-Shadowserver-Foundation/api_utils/wiki/API:-Reports-Query
 - https://interchange.shadowserver.org/schema/reports.json

 The integration creates the following types of Stix objects and relationships between them.
 - Artifact
 - AutonomousSystem
 - CustomObjectCaseIncident (optional)
 - DomainName
 - Identity
 - IPv4Address
 - IPv6Address
 - MACAddress
 - MarkingDefinition
 - NetworkTraffic
 - Note
 - ObservedData
 - Report
 - Vulnerability
 - X509Certificate

On the initial run, the integration defaults to the last 30-days of reports. Every run after that, it provides an update for the last 3-days. 

## Installation

### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

Configuration parameters are provided using environment variables as described below.
Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.

Note that the values that follow can be grabbed within Python code using `self.helper.{PARAMETER}`, i. e., `self.helper.connector_nane`.

Expected environment variables to be set in the  `docker-compose.yml` that describe the connector itself.
Most of the times, these values are NOT expected to be changed.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                                                                                                    |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | A connector name to be shown in OpenCTI.                                                                                                                   |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope. E. g., `text/html`.                                                                                                                       |

However, there are other values which are expected to be configured by end users.
The following values are expected to be defined in the `.env` file.
This file is included in the `.gitignore` to avoid leaking sensitive date). 
Note tha the `.env.sample` file can be used as a reference.

The ones that follow are connector's generic execution parameters expected to be added for export connectors.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                               |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `interval`                           | `CONNECTOR_RUN_EVERY`               | Yes          | The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., 30s is 30 seconds. 1d is 1 day.                                                                                  |
| `update_existing_data`               | `CONNECTOR_UPDATE_EXISTING_DATA`    | Yes          | Whether to update known existing data.                                                                                                                     |


Finally, the ones that follow are connector's specific execution parameters expected to be used by this connector.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shadowserver_api_key`               | `SHADOWSERVER_API_KEY`              | Yes          | The API key for Shadowserver.                                                                                                                              |
| `shadowserver_api_secret`            | `SHADOWSERVER_API_SECRET`           | Yes          | The API secret for Shadowserver.                                                                                                                           |
| `shadowserver_marking`               | `SHADOWSERVER_MARKING`              | Yes          | The marking for the data, e.g., `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`.                                                                                                               |
| `shadowserver_create_incident`       | `SHADOWSERVER_CREATE_INCIDENT`      | Yes          | Whether to create an incident (`true` or `false`).                                                                                                         |
| `shadowserver_incident_severity`     | `SHADOWSERVER_INCIDENT_SEVERITY`    | Yes          | The severity of the incident, e.g., `low` (Default: `low`).                                                                                                                 |
| `shadowserver_incident_priority`     | `SHADOWSERVER_INCIDENT_PRIORITY`    | Yes          | The priority of the incident, e.g., `P4` (Default: `P4`).   

### Debugging ###

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.log_{LOG_LEVEL}("Sample message")`, i. e., `self.helper.log_error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->