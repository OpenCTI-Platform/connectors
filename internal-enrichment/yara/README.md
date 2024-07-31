# OpenCTI YARA Connector

This OpenCTI connector enriches Artifact Observables by scanning their
contents using every YARA Indicator in the system. When a rule matches, the
connector creates a relationship between the Artifact and Indicator.

<https://virustotal.github.io/yara/>

## Installation

### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Set to "YARA"
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Artifact
| `connector_auto`                    | `CONNECTOR_AUTO`                   | Yes          | Enable or disable auto-enrichment
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created relationships (a number between 1 and 100).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
