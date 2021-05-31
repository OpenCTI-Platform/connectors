# OpenCTI Elasticsearch connector

This connector allows organizations to feed a **Elasticsearch** using OpenCTI knowledge. 

## Installation

### Requirements

- OpenCTI Platform >= 4.5.4

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `STREAM` (this is the connector type).                                                                                                             |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the Elasticsearch instance, to identify it if you have multiple Elasticsearch connectors.                                                                    |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `elasticsearch`, not used in this connector.                                                                                                              |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `elasticsearch_url`                  | `ELASTICSEARCH_URL`                 | Yes          | The Elasticsearch instance URL                                                                                                                                   |
| `elasticsearch_ssl_verify`           | `ELASTICSEARCH_SSL_VERIFY`          | Yes          | Enable the SSL certificate check (default: `true`)                                                                                                         |
| `elasticsearch_login`                | `ELASTICSEARCH_LOGIN`               | No           | The Elasticsearch login user.                                                                                                                                     |
| `elasticsearch_password`             | `ELASTICSEARCH_PASSWORD`            | No           | The Elasticsearch password.                                                                                                                                       |
| `elasticsearch_index`                | `ELASTICSEARCH_INDEX`               | Yes          | The Elasticsearch index name.                                                                                                                                 |