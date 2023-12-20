# OpenCTI Crowdstrike connector

This connector allows to push IOC from OpenCTI to Crowdstrike.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                              | Docker envvar                          | Mandatory    | Description                                                                                   |
| -------------------------------------- | -------------------------------------- | ------------ |-----------------------------------------------------------------------------------------------|
| `opencti_url`                          | `OPENCTI_URL`                          | Yes          | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                        | `OPENCTI_TOKEN`                        | Yes          | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                         | `CONNECTOR_ID`                         | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`                       | `CONNECTOR_TYPE`                       | Yes          | Must be `STREAM` (this is the connector type).                                                |
| `connector_name`                       | `CONNECTOR_NAME`                       | Yes          | Connector name.       |
| `connector_scope`                      | `CONNECTOR_SCOPE`                      | Yes          | Must be `crowdstrike`, not used in this connector.                                            |
| `connector_confidence_level`           | `CONNECTOR_CONFIDENCE_LEVEL`           | Yes          | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                  | `CONNECTOR_LOG_LEVEL`                  | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`             | `CONNECTOR_CONSUMER_COUNT`             | No           | Number of consumer/worker that will push data.                                      |
| `connector_live_stream_start_timestamp`| `CONNECTOR_LIVE_STREAM_START_TIMESTAMP`| No           | Start timestamp used on connector first start.                                                |
| `crowdstrike_client_id`                | `CROWDSTRIKE_CLIENT_ID`                | Yes          | Crowdstrike client ID used to connect to the API.                                             |
| `crowdstrike_client_secret`            | `CROWDSTRIKE_CLIENT_SECRET`            | Yes          | Crowdstrike client secret used to connect to the API.                                         |
| `metrics_enable`                       | `METRICS_ENABLE`                       | No           | Whether or not Prometheus metrics should be enabled.                                          |
| `metrics_addr`                         | `METRICS_ADDR`                         | No           | Bind IP address to use for metrics endpoint.                                                  |
| `metrics_port`                         | `METRICS_PORT`                         | No           | Port to use for metrics endpoint.                                                             |

