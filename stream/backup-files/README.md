# Files backup connector

This connector allows organizations to consume their OpenCTI data and write them to a specific folder.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0
- A directory accessible by the Python script with write access

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The token of the OpenCTI user (it's recommanded to create a dedicated user for the connector with the Administrator role).                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `STREAM` (this is the connector type).                                                                                                             |
| `connector_live_stream_id`           | `CONNECTOR_LIVE_STREAM_ID`          | Yes          | The Live Stream ID of the stream created in the OpenCTI interface                                                                                          |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the remote OpenCTI instance for example.                                |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `synchronizer`, not used in this connector.                                                                                                              |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `backup_protocol`                    | `BACKUP_PROTOCOL`                   | Yes          | Protocol for file copy (only `local` is supported for now).                                                                                                                                   |
| `backup_path`                        | `BACKUP_PATH`                       | Yes          | Path to be used to copy the data, can be relative or absolute.          |
| `backup_login`                       | `BACKUP_LOGIN`                      | No           | The login if the selected protocol need login auth.                                                                                                                                       |
| `backup_password`                    | `BACKUP_PASSWORD`                   | No           | The password if the selected protocol need login auth. |
