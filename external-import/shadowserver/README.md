# Shadowserver Connector

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified |      | -       |

The integration uses Shadowservers reports API to query the available Shadowserver reports and transform them into Stix
objects making them available within OpenCTI. All available reports are downloaded and an `Artifact` object is created
with the original file. Stix `Note` objects are added to both the `Report` and the `CustomObjectCaseIncident` with a
mark-down rendition of each finding from the report.

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

On the initial run, the integration defaults to the last 30-days of reports. Every run after that, it provides an update
for the last 3-days.

## Installation

### Requirements

- Subscribe to
  Shadowserver [Shadowserver Reports](https://www.shadowserver.org/what-we-do/network-reporting/get-reports/)

### Configuration

Configuration parameters can be provided in either **`.env`** file, **`config.yml`** file, or directly as **environment
variables**.

Priority: **YAML → .env → environment → defaults**.

#### OpenCTI Configuration

| Parameter     | `config.yml` key | Env var         | Required | Description                      |
|---------------|------------------|-----------------|----------|----------------------------------|
| OpenCTI URL   | `url`            | `OPENCTI_URL`   | ✅        | Base URL of the OpenCTI platform |
| OpenCTI Token | `token`          | `OPENCTI_TOKEN` | ✅        | API token (user or connector)    |

#### Base Connector Configuration

| Parameter                 | `config.yml` key  | Env var                     | Default      | Required | Description                                                                                                                                                                       |
|---------------------------|-------------------|-----------------------------|--------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID              | `id`              | `CONNECTOR_ID`              | —            | ✅        | Unique **UUIDv4** for this connector instance                                                                                                                                     |
| Connector Name            | `name`            | `CONNECTOR_NAME`            | Shadowserver | ❌        | Display name                                                                                                                                                                      |
| Connector Scope           | `scope`           | `CONNECTOR_SCOPE`           | stix2        | ❌        | Import label shown in jobs                                                                                                                                                        |
| Log Level                 | `log_level`       | `CONNECTOR_LOG_LEVEL`       | error        | ❌        | `debug` \| `info` \| `warning` \| `error`                                                                                                                                         |
| Duration Period           | `duration_period` | `CONNECTOR_DURATION_PERIOD` | P1D          | ❌        | ISO‑8601 duration                                                                                                                                                                 |
| ~~Interval~~ ⚠️Deprecated | ~~/~~             | ~~`CONNECTOR_RUN_EVERY`~~   | ~~1d~~       | ~~❌~~    | ~~The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., 30s is 30 seconds. 1d is 1 day.~~ |

#### Shadow Server Configuration

| Parameter         | `config.yml` key                 | Env var                          | Default   | Required | Description                                                                       |
|-------------------|----------------------------------|----------------------------------|-----------|----------|-----------------------------------------------------------------------------------|
| API Key           | `shadowserver_api_key`           | `SHADOWSERVER_API_KEY`           | —         | ✅        | The API key for Shadowserver.                                                     |
| API Secret        | `shadowserver_api_secret`        | `SHADOWSERVER_API_SECRET`        | —         | ✅        | The API secret for Shadowserver.                                                  |
| Marking           | `shadowserver_marking`           | `SHADOWSERVER_MARKING`           | TLP:CLEAR | ❌        | The marking for the data, e.g., `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`. |
| Create Incident   | `shadowserver_create_incident`   | `SHADOWSERVER_CREATE_INCIDENT`   | false     | ❌        | Whether to create an incident (`true` or `false`).                                |
| Incident Severity | `shadowserver_incident_severity` | `SHADOWSERVER_INCIDENT_SEVERITY` | low       | ❌        | The severity of the incident.                                                     |
| Incident Priority | `shadowserver_incident_priority` | `SHADOWSERVER_INCIDENT_PRIORITY` | P4        | ❌        | The priority of the incident.                                                     |

### Debugging ###

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message", meta={})`, i.
e., `self.helper.connector_logger.error("An error message", meta={"error": e})`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
