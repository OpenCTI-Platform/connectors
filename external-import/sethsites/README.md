# OpenCTI Template Connector

This connector is designed to scan an existing elasticsearch environment for previous attacks and then continue
to scan new documents for evidence of ongoing attacks.

It looks for evidence of ping sweeps, port scans, http attacks, unauthorized modbus traffic.  It uses this data to 
perform a more thorough examination of documents during the time of these incidents to attempt to identify host 
compromises and lateral transfers.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.1

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `Template_Type` (this is the connector type).                                                                                                      |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `Template`                                                                                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                 |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 100).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `template_attribute`                 | `TEMPLATE_ATTRIBUTE`                | Yes          | Additional setting for the connector itself                                                                                                                |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector --> 

### Additional information

<!-- 
Any additional information about this connector 
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

