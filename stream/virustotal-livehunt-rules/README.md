# OpenCTI VirusTotal Livehunt Stream connector

This connector allows organizations to create and manage VirusTotal Livehunts from OpenCTI. 
When enabling a Yara rule in OpenCTI automatically it does create a new Livehunt in VirusTotal.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                   |
| ------------------------------------ | ----------------------------------- | ------------ |-----------------------------------------------------------------------------------------------|
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `STREAM` (this is the connector type).                                                |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the VirusTotal Livehunt Stream instance, to identify it if you have multiple VirusTotal Livehunt connectors.       |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `Yara`, not used in this connector.                                                 |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `virustotal_livehunt_token`          | `VIRUSTOTAL_LIVEHUNT_TOKEN`         | No          | The VirusTotal API token                                                                      |
| `virustotal_livehunt_notification_emails` |`VIRUSTOTAL_LIVEHUNT_NOTIFICATION_EMAILS`         | Yes          | List of emails to receive notifications when the rule gets triggered                                                                                      |
| `virustotal_livehunt_shared_owners`  | `VIRUSTOTAL_LIVEHUNT_SHARED_OWNERS` | No          | Existing Virustotal users ID that the rule will be shared with                                 |