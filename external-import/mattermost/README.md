# Mattermost Connector

This connector imports messages and their attachments from multiple discussion threads originating from a Mattermost instant messaging server.

The content of each message is stored in  a "Media Content" entity, to which any attached images and documents are associated. Each message is linked to a "Channel" entity representing the discussion thread. Message authors are imported as STIX2 "Individual" entities, which are linked to the messages.

To perform this data collection, you must give:
• the server URL,
• the identifiers of the threads to be imported,
• a login token from a Mattermost service user account. This account must have read permissions for the collected threads.


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
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | A connector name to be shown in OpenCTI. E.g.: `mattermost-connector`                                                                                                                   |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope. E. g., `mattermost`.                                                                                                                       |

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

Finally, the ones that follow are connector's specific execution parameters expected to be used by this connector.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mattermost_domain`                    | `MATTERMOST_DOMAIN`                   | Yes          | For example: `my-mattermost-chat.fr`.                                                                                                                                       |
| `mattermost_port`                    | `MATTERMOST_PORT`                   | No          | `8065` is the default value.                                                                                                                                       |
| `mattermost_protocol`                    | `MATTERMOST_PROTOCOL`                   | No          | `http` or `https`. The last one is the default value.                                                                                                                                       |
| `mattermost_basepath`                    | `MATTERMOST_BASEPATH`                   | No          | Web base path for the mattermost service. `/api/v4` is the default value.                                                                                                                                     |
| `mattermost_token`                    | `MATTERMOST_TOKEN`                   | Yes          | Access token of a mattermost account.                                                                                                                                       |
| `mattermost_channel_ids`                    | `MATTERMOST_CHANNEL_IDS`                   | Yes          | Mattermost channel ids separated by a comma. E.g: `5i5rip6zaf8qprwfi86iu9xsjy,ztu3g3f4upgjxezhsuqe5imzpr`. Obviously, the token must have the right to access those channels.                                                                                                                                      |
| `mattermost_start_timestamp`                    | `MATTERMOST_START_TIMESTAMP`                   | No          | Initial start time for retrieving the mattermost messages. The format of the timestamp is Unix epoch, in seconds. E.g.: `1708954724`. Default value is `0`.                                                                                                                                      |
| `mattermost_tlp`                    | `MATTERMOST_TLP`                   | No          | `CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT` or `RED`. Default value is `AMBER`.                                                                                                                                       |
| `mattermost_verify`                    | `MATTERMOST_VERIFY`                   | No          | Parameter to force web certificate verification. Can be `true` of `false`. Default value is `true`.                                                                                                                                       |                                                                                                                                       |
| `mattermost_timeout`                    | `MATTERMOST_TIMEOUT`                   | No          | Default value is `30` seconds. If for some reasons you get regular timeouts after a while, try to change this value. The websocket will ping the server in this interval to keep the connection alive. If you have access to your server configuration, you can of course increase the timeout there.                                                                                                                                        |
| `mattermost_request_timeout`                    | `MATTERMOST_REQUEST_TIMEOUT`                   | No          | This value controls the request timeout.                                                                                                                                       |
| `mattermost_keepalive`                    | `MATTERMOST_KEEPALIVE`                   | No          | To keep the websocket connection alive even if it gets disconnected for some reason you can set the keepalive option to `true`. Default value is `false`.                                                                                                                                       |
| `mattermost_keepalive_delay`                    | `MATTERMOST_KEEPALIVE_DELAY`                   | No          | The mattermost_keepalive_delay defines how long to wait in seconds before attempting to reconnect the websocket.                                                                                                                                       |
| `mattermost_debug`                    | `MATTERMOST_DEBUG`                   | No          | Default value is `false`. Setting debug to `true`, will activate a very verbose logging.This also activates the logging for the requests package, so you can see every request you send. This SHOULD NOT be active in production, because this logs a lot, even passwords and tokens.                                                            .                                                                           |
