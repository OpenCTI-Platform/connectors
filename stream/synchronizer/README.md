# OpenCTI to OpenCTI synchronizer connector

This connector allows organizations to synchronize their OpenCTI with a remote OpenCTI instance using live streams.

## Installation

### Requirements

- Local OpenCTI Platform >= 5.0.0
- Remote OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the local OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The token of the local OpenCTI user (it's recommanded to create a dedicated user for the connector with the Administrator role).                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `STREAM` (this is the connector type).                                                                                                             |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the remote OpenCTI instance for example.                                |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `synchronizer`, not used in this connector.                                                                                                              |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `remote_openct_url`                  | `REMOTE_OPENCTI_URL`                | Yes          | The remote OpenCTI instance URL.                                                                                                                                   |
| `remote_opencti_live_stream_id`      | `REMOTE_OPENCTI_LIVE_STREAM_ID`     | Yes          | ID of the live stream (can be `live`, which is the default recommanded value)   |
| `remote_opencti_ssl_verify`          | `REMOTE_OPENCTI_SSL_VERIFY`         | Yes          | Enable SSL check when connecting to the remote OpenCTI instance                                                                                                                                   |
| `remote_opencti_token`               | `REMOTE_OPENCTI_TOKEN`              | Yes          | The remote OpenCTI token.                                                                                                                                       |
| `remote_opencti_start_timestamp`     | `REMOTE_OPENCTI_START_TIMESTAMP`    | No           | Optional, start to synchronize from a specific date                                                                                          |
