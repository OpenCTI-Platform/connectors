# OpenCTI webhook connector

This connector allows organizations to relay events to other systems (SOAR etc ..) thought post messages

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0

### Configuration

| Parameter                               | Docker envvar                           | Mandatory    | Description                                                                              |
|-----------------------------------------|-----------------------------------------| ------------ |------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes          | The URL of the OpenCTI platform.                                                         |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes          | The default admin token configured in the OpenCTI platform parameters file.              |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                       |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes          | The name of the webhook instance, to identify it if you have multiple webhook connectors.  |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes          | Must be `webhook`, not used in this connector.                                            |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes          | The default confidence level for created sightings (a number between 1 and 4).           |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No           | Number of consumer/worker that will push data to webhook.                        |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No           | Start timestamp used on connector first start.                                           |
| `webhook_type`                          | `WEBHOOK_TYPE`                          | Yes          | The type of webhook integration (Only URL now)                                      |
| `webhook_url`                           | `WEBHOOK_URL`                           | Yes          | If WEBHOOK_TYPE=URL, mandatory. The adress of the destination                                    |
| `webhook_token`                         | `WEBHOOK_TOKEN`                         | No           | The value of the token                                             |
| `webhook_header`                        | `WEBHOOK_HEADER`                        | No           | If WEBHOOK_AUTH_TYPE=Token, he name of the header where the token will be put                                               |
| `webhook_auth_ype`                      | `WEBHOOK_AUTH_TYPE`                     | No           | The type of auth used 'NONE', 'TOKEN'                                               |
| `metrics_enable`                        | `METRICS_ENABLE`                        | No           | Whether or not Prometheus metrics should be enabled.                                     |
| `metrics_addr`                          | `METRICS_ADDR`                          | No           | Bind IP address to use for metrics endpoint.                                             |
| `metrics_port`                          | `METRICS_PORT`                          | No           | Port to use for metrics endpoint.                                                        |