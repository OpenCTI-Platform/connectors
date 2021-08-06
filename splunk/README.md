# OpenCTI Splunk connector

This connector allows organizations to feed a **Splunk** KV Store using OpenCTI knowledge. 

## Installation

### Requirements

- OpenCTI Platform >= 4.5.5

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `STREAM` (this is the connector type).                                                                                                             |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the Splunk instance, to identify it if you have multiple Splunk connectors.                                                                    |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `splunk`, not used in this connector.                                                                                                              |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `splunk_url`                         | `SPLUNK_URL`                        | Yes          | The Splunk instance REST API URL (default port is 8089).                                                                                                   |
| `splunk_ssl_verify`                  | `SPLUNK_SSL_VERIFY`                 | Yes          | Enable the SSL certificate check (default: `true`)                                                                                                         |
| `splunk_login`                       | `SPLUNK_LOGIN`                      | Yes          | The Splunk login user.                                                                                                                                     |
| `splunk_password`                    | `SPLUNK_PASSWORD`                   | Yes          | The Splunk password.                                                                                                                                       |
| `splunk_owner`                       | `SPLUNK_OWNER`                      | Yes          | The owner of the KV Store.                                                                                                                                 |
| `splunk_app`                         | `SPLUNK_APP`                        | Yes          | The app of the KV Store.                                                                                                                                   |
| `splunk_kv_store_name`               | `SPLUNK_KV_STORE_NAME`              | Yes          | The name of the KV Store.                                                                                                                                  |