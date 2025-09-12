# Matrix Connector

This connector imports messages and their attachments from multiple discussion threads originating from a Matrix instant messaging server.

The content of each message is stored in  a "Media Content" entity, to which any attached images and documents are associated. Each message is linked to a "Channel" entity representing the discussion thread. Message authors are imported as STIX2 "Individual" entities, which are linked to the messages.

To perform this data ingestion, you must have:
- a Matrix bot account that is member of the discussion threads that need to be collected
- the Matrix server URL.


## Installation

### Requirements

- OpenCTI Platform >= 6.4.3

### Configuration

Configuration parameters are provided using environment variables as described below.
Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.

Note that the values that follow can be grabbed within Python code using `self.helper.{PARAMETER}`, i. e., `self.helper.connector_nane`.

Expected environment variables to be set in the  `docker-compose.yml` that describe the connector itself.
Most of the times, these values are NOT expected to be changed.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | A connector name to be shown in OpenCTI. E.g.: `matrix-connector`                                                                                                                   |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope. E. g., `matrix`.                                                                                                                       |

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

Finally, the ones that follow are connector's specific execution parameters expected to be used by this connector.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `matrix_server`                    | `MATRIX_SERVER`                   | Yes          | For example: `https://matrix.agent.tchap.gouv.fr`.                                                                                                                                       |
| `matrix_device_name`                    | `MATRIX_DEVICE_NAME`                   | No          | Device name of the Matrix Client. Default is `octi_bot`.                                                                                                                                     |
| `matrix_user_id`                    | `MATRIX_USER_ID`                   | Yes          | User ID of the bot account. For example: `@octi-bot:agent.tchap.gouv.fr`                                                                                                                                       |
| `matrix_password`                    | `MATRIX_PASSWORD`                   | Yes          | Password of the bot account.                                                                                                                                      |
| `matrix_tlp`                    | `MATRIX_TLP`                   | No          | `CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT` or `RED`. Default value is `AMBER`.                                                                                                                                       |
| `matrix_debug`                    | `MATRIX_DEBUG`                   | No          | Default value is `false`. Setting debug to `true`, will activate a very verbose logging.This also activates the logging for the requests package, so you can see every request you send. This SHOULD NOT be active.                                                            .                                                                           |
