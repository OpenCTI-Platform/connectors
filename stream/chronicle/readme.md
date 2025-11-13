 OpenCTI Chronicle connector

This connector allows organizations to relay events to Google Chronicle
## Installation

### Requirements

- OpenCTI Platform >= 6.0.0

### Configuration

| Parameter                               | Docker envvar                           | Mandatory    | Description                                                                              |
|-----------------------------------------|-----------------------------------------| ------------ |------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes          | The URL of the OpenCTI platform.                                                         |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes          | The default admin token configured in the OpenCTI platform parameters file.              |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                       |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes          | The name of the webhook instance, to identify it if you have multiple webhook connectors.|
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes          | Must be `webhook`, not used in this connector.                                           |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes          | The default confidence level for created sightings (a number between 1 and 4).           |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No           | Number of consumer/worker that will push data to webhook.                                |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No           | Start timestamp used on connector first start.                                           |
| `chronicle_url`                         | `CHRONICLE_URL`                         | Yes          | The type of webhook integration (Only URL now)                                           |
| `chronicle_list_name`                   | `CHRONICLE_LIST_NAME`                   | Yes          | List which will be enriched                                                              |
| `chronicle_project_id`                  | `CHRONICLE_PROJECT_ID`                  | Yes          | project_id in account.json file                                                          |
| `chronicle_auth_uri`                    | `CHRONICLE_AUTH_URI`                    | Yes          | auth_uri in in account.json file                                                         |
| `chronicle_token_uri`                   | `CHRONICLE_TOKEN_URI`                   | Yes          | token_uri in  account.json file                                                          |
| `chronicle_auth_provider_cert`          | `CHRONICLE_AUTH_PROVIDER_CERT`          | Yes          | auth_cert_provider in account.json file                                                  |
| `chronicle_ignore_types`                | `CHRONICLE_IGNORE_TYPES`                | Yes          | ignored types in the stream.                                                             |
| `chronicle_private_key_id`              | `CHRONICLE_PRIVATE_KEY_ID`              | Yes          | private_key_id in account.json file                                                      |
| `chronicle_private_key`                 | `CHRONICLE_PRIVATE_KEY`                 | Yes          | private_key in account.json file                                                         |
| `chronicle_client_email`                | `CHRONICLE_CLIENT_EMAIL`                | Yes          | client_email in account.json file                                                        |
| `chronicle_client_id`                   | `CHRONICLE_CLIENT_ID`                   | Yes          | client_id in account.json file                                                           |
| `chronicle_client_cert_url`             | `CHRONICLE_CLIENT_CERT_URL`             | Yes          | client_cert_url in account.json file                                                     |
| `metrics_enable`                        | `METRICS_ENABLE`                        | No           | Whether or not Prometheus metrics should be enabled.                                     |
| `metrics_addr`                          | `METRICS_ADDR`                          | No           | Bind IP address to use for metrics endpoint.                                             |
| `metrics_port`                          | `METRICS_PORT`                          | No           | Port to use for metrics endpoint.                                                        |